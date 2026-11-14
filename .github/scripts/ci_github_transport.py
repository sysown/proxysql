"""Bounded gh API transport used by CI orchestration."""
from email.utils import parsedate_to_datetime
from contextlib import contextmanager
from contextvars import ContextVar
import json
import os
import re
import subprocess
import sys
import time
from threading import Lock
from urllib.parse import urlsplit


MAX_ATTEMPTS = 6
MAX_WAIT_SECONDS = 1200
_QUOTA_HEADERS = ('x-ratelimit-limit', 'x-ratelimit-remaining',
                  'x-ratelimit-used', 'x-ratelimit-reset')
_TRANSIENT = ('connection reset', 'i/o timeout', 'tls handshake timeout',
              'unexpected eof', 'connection timed out',
              'temporary failure in name resolution')

_COMMAND_BUDGET = ContextVar('github_command_budget', default=None)


def current_budget():
    return _COMMAND_BUDGET.get()


def effective_deadline(deadline=None, budget=None):
    budget = budget if budget is not None else current_budget()
    deadlines = [value for value in (deadline, budget.deadline if budget else None)
                 if value is not None]
    return min(deadlines) if deadlines else None


def clipped_timeout(seconds, deadline=None, budget=None):
    deadline = effective_deadline(deadline, budget)
    if deadline is None:
        return seconds
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError('GitHub API command deadline exceeded')
    return min(seconds, remaining)


class CommandBudget:
    """One deadline and retry-wait allowance, shared with download workers."""
    def __init__(self, deadline=None):
        self.deadline = deadline
        self.waited = 0
        self.lock = Lock()

    def wait(self, delay, *, cancelled=None, deadline=None):
        with self.lock:
            if delay > MAX_WAIT_SECONDS - self.waited:
                raise RuntimeError('GitHub API retry wait budget exceeded')
            remaining = clipped_timeout(float('inf'), deadline, self)
            if delay >= remaining:
                raise RuntimeError('GitHub API command deadline exceeded before retry wait')
            # Reserve before sleeping so concurrent workers cannot overspend.
            self.waited += delay
        started = time.monotonic()
        if cancelled is None:
            time.sleep(delay)
        elif cancelled.wait(delay):
            elapsed = min(delay, max(0, time.monotonic() - started))
            with self.lock:
                self.waited -= delay - elapsed
            raise RuntimeError('artifact download cancelled')
        clipped_timeout(float('inf'), deadline, self)


@contextmanager
def command_budget(timeout_seconds=1500):
    """Bound a command's I/O and total API retry waits across all clients."""
    inherited = current_budget()
    budget = inherited or CommandBudget(time.monotonic() + timeout_seconds)
    token = _COMMAND_BUDGET.set(budget)
    try:
        yield budget
        clipped_timeout(float('inf'), budget=budget)
    finally:
        _COMMAND_BUDGET.reset(token)


def _response(data):
    """Strip consecutive redirect/interim header blocks without decoding a body."""
    status, headers = None, {}
    while True:
        match = re.match(rb'HTTP/\S+\s+(\d{3})[^\r\n]*\r?\n', data)
        if not match:
            return status, headers, data
        end = re.search(rb'\r?\n\r?\n', data)
        if not end:
            return status, headers, data
        status = int(match[1])
        quota = {name: headers[name] for name in _QUOTA_HEADERS if name in headers}
        headers = {}
        for line in data[match.end():end.start()].splitlines():
            name, sep, value = line.partition(b':')
            if sep:
                headers[name.decode('ascii', errors='ignore').lower()] = value.decode('latin1').strip()
        for name, value in quota.items():
            headers.setdefault(name, value)
        data = data[end.end():]
        if not (100 <= status < 200 or 300 <= status < 400):
            return status, headers, data


def _endpoint(path, token):
    # Neither URL credentials nor query parameters belong in CI logs.
    endpoint = urlsplit(path).path
    for secret in (token, os.environ.get('GH_TOKEN'), os.environ.get('GITHUB_TOKEN')):
        if secret:
            endpoint = endpoint.replace(secret, '[REDACTED]')
    endpoint = re.sub(r'(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+', '[REDACTED]', endpoint)
    return re.sub(r'[^A-Za-z0-9_./%\[\]-]', '_', endpoint)[:300]


def is_rate_limited(status, headers, diagnostic=''):
    """Recognize explicit rejections shared by gh and urllib callers."""
    headers = {name.lower(): value for name, value in headers.items()}
    return status == 429 or (status == 403 and (
        'retry-after' in headers or headers.get('x-ratelimit-remaining') == '0'
        or 'rate limit' in diagnostic.lower()))


def retry_delay(headers, limited, attempt):
    """Return a wait in seconds; callers enforce their cumulative wait budget."""
    headers = {name.lower(): value for name, value in headers.items()}
    if limited:
        retry_after = headers.get('retry-after', '')
        if retry_after.isdecimal():
            return int(retry_after)
        if retry_after:
            try:
                return max(0, parsedate_to_datetime(retry_after).timestamp() - time.time())
            except (ValueError, TypeError, OverflowError):
                pass
        reset = headers.get('x-ratelimit-reset', '')
        if headers.get('x-ratelimit-remaining') == '0' and reset.isdecimal():
            return max(0, int(reset) - time.time())
        # GitHub requests at least a minute for secondary limits without hints.
        return 60 * (2 ** attempt)
    return min(30, 2 ** attempt)


def request(path, method='GET', payload=None, raw=False, *, token=None,
            retry_safe=False, before_retry=None, deadline=None):
    """Run gh with bounded retries; only stable PATCH writes opt into replay."""
    if retry_safe and method != 'PATCH':
        raise ValueError('retry_safe requires PATCH')
    args = ['gh', 'api', path, '--method', method, '--include']
    if payload is not None:
        args += ['--input', '-']
    endpoint = _endpoint(path, token)
    budget = current_budget() or CommandBudget(deadline)
    deadline = effective_deadline(deadline, budget)
    for attempt in range(MAX_ATTEMPTS):
        clipped_timeout(float('inf'), deadline, budget)
        if attempt and before_retry is not None:
            before_retry()
        headers = {}
        status = None
        try:
            result = subprocess.run(args,
                input=json.dumps(payload).encode() if payload is not None else None,
                capture_output=True, timeout=clipped_timeout(900 if raw else 60, deadline, budget),
                env=dict(os.environ, GH_TOKEN=token) if token else None)
        except subprocess.TimeoutExpired:
            reason, limited = 'timed out', False
            retryable = method == 'GET' or retry_safe
        else:
            clipped_timeout(float('inf'), deadline, budget)
            status, headers, body = _response(result.stdout)
            error = result.stderr.decode(errors='replace').lower()
            if status is None:
                match = re.search(r'\bhttp\s+(\d{3})\b', error)
                if match:
                    status = int(match[1])
            limited = is_rate_limited(status, headers, error + (
                ' ' + body.decode(errors='replace') if status == 403 else ''))
            reason = f'exit {result.returncode}' + (f' HTTP {status}' if status else '')
            read_limit = limited or (status is None and 'rate limit' in error)
            transient = read_limit or status in (500, 502, 503, 504) or any(
                marker in error for marker in _TRANSIENT)
            retryable = transient if method == 'GET' or retry_safe else limited
            limited = read_limit
            # gh diagnostics can echo tokens, payloads, and signed URLs. Report
            # only structured status/quota fields, never arbitrary stderr/body.
            if not result.returncode:
                _metric(method, endpoint, status, headers)
                return body if raw else json.loads(body or b'{}')
        _metric(method, endpoint, status, headers)
        diagnostic = f'GitHub API {method} {endpoint}: {reason} after {attempt + 1} attempts'
        if not retryable or attempt == MAX_ATTEMPTS - 1:
            raise RuntimeError(diagnostic) from None
        delay = retry_delay(headers, limited, attempt)
        print(f'GitHub API {method} {endpoint}: retrying in {delay:g}s',
              file=sys.stderr, flush=True)
        budget.wait(delay, deadline=deadline)


def record_response(method, path, status, headers, *, token=None):
    """Account for direct artifact requests using the same safe log fields."""
    _metric(method, _endpoint(path, token), status,
            {name.lower(): value for name, value in headers.items()})


def _metric(method, endpoint, status, headers):
    quota = ''.join(f' {name}={headers[name]}' for name in _QUOTA_HEADERS
                    if headers.get(name, '').isascii() and headers.get(name, '').isdecimal())
    print(f'GitHub API {method} {endpoint} status={status or "unknown"}{quota}',
          file=sys.stderr, flush=True)
