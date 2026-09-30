#!/usr/bin/env python3
"""Run-scoped GitHub API and handoff operations. Never select by newest SHA."""
import io
import concurrent.futures
import hashlib
import re
from threading import Event
import http.client
import json
import os
import posixpath
import shutil
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile
import time
import zipfile
import uuid
import urllib.error
import urllib.request
from ci_tier_plan import validate_manifest, version_tuple

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Resolve the signed storage URL without forwarding the GitHub token.
        return None

# Avoid multiple connections for small artifacts; large handoffs use eight.
MIN_DOWNLOAD_PART_BYTES=64*1024*1024

class RangeUnsupported(Exception):
    """The storage server ignored a bounded range; retry as one stream."""


def download_timeout(deadline,cancelled=None):
    if cancelled is not None and cancelled.is_set():
        raise RuntimeError('artifact download cancelled')
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('download deadline')
    return min(60,remaining)


def artifact_location(url,token,deadline,cancelled):
    # Never send GitHub credentials to the signed storage URL.
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token})
    try:
        response=urllib.request.build_opener(NoRedirect()).open(
            request,timeout=download_timeout(deadline,cancelled))
    except urllib.error.HTTPError as error:
        if error.code!=302:raise
        response=error
    with response:
        if response.code!=302:raise ValueError('artifact endpoint did not redirect')
        return response.headers['Location']


def download_part(url,token,target,start,end,size,deadline,cancelled,parallel):
    with target.open('w+b') as out:
        for attempt in range(6):
            try:
                location=artifact_location(url,token,deadline,cancelled)
                offset=start+out.tell()
                request=urllib.request.Request(location,headers={
                    'Range':f'bytes={offset}-{end if parallel else ""}'})
                with urllib.request.urlopen(request,timeout=download_timeout(deadline,cancelled)) as response:
                    if response.status==200:
                        if parallel:raise RangeUnsupported()
                        out.seek(0);out.truncate();offset=0
                    elif response.status!=206 or response.headers.get('Content-Range')!=f'bytes {offset}-{end}/{size}':
                        raise ValueError('unexpected artifact byte range')
                    print(f'Artifact range {start}-{end}, attempt {attempt+1}: {out.tell()}/{end-start+1} bytes',flush=True)
                    reported=out.tell()
                    while True:
                        download_timeout(deadline,cancelled)
                        chunk=response.read1(1024*1024)
                        if not chunk:break
                        if out.tell()+len(chunk)>end-start+1:
                            raise ValueError('artifact exceeds expected range size')
                        out.write(chunk)
                        if out.tell()-reported>=256*1024*1024:
                            reported=out.tell()
                            print(f'Artifact range {start}-{end}: {reported}/{end-start+1} bytes',flush=True)
                if out.tell()!=end-start+1:raise OSError('incomplete artifact download')
                return
            except (OSError,http.client.HTTPException) as error:
                # Never log exceptions containing signed URLs or credentials.
                reason=f'HTTP {error.code}' if isinstance(error,urllib.error.HTTPError) else type(error).__name__
                if isinstance(error,urllib.error.HTTPError):error.close()
                remaining=deadline-time.monotonic()
                if attempt==5 or remaining<=0:
                    raise RuntimeError(f'Artifact download failed ({reason}); range {start}-{end} received {out.tell()} bytes') from None
                print(f'Artifact range {start}-{end} interrupted ({reason}); resuming at {out.tell()} bytes',flush=True)
                if cancelled.wait(min(30,2**attempt,remaining)):
                    raise RuntimeError('artifact download cancelled') from None


def download_parts(url,token,folder,size,workers,deadline):
    cancelled=Event()
    chunk=(size+workers-1)//workers
    parts=[folder/f'part-{i}' for i in range(workers)]
    if workers==1:
        download_part(url,token,parts[0],0,size-1,size,deadline,cancelled,False)
        return parts
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures=[pool.submit(download_part,url,token,part,i*chunk,
                min(size-1,(i+1)*chunk-1),size,deadline,cancelled,True)
                for i,part in enumerate(parts)]
            try:
                for future in concurrent.futures.as_completed(futures):future.result()
            finally:
                # Stop peers before cleaning scratch files or starting fallback.
                cancelled.set()
                for future in futures:future.cancel()
    except RangeUnsupported:
        print('Artifact storage ignored ranges; falling back to one stream',flush=True)
        for part in parts:part.unlink(missing_ok=True)
        return download_parts(url,token,folder,size,1,deadline)
    return parts


class GitHubAPI:
    def __init__(self, repository, token=None):
        self.repository=repository
        self.token=token
    def request(self,path,method='GET',payload=None,raw=False):
        args=['gh','api',path,'--method',method]
        if payload is not None:args+=['--input','-']
        attempts=6
        for attempt in range(attempts):
            try:
                result=subprocess.run(args,input=json.dumps(payload).encode() if payload is not None else None,
                    capture_output=True,timeout=900 if raw else 60,
                    env=dict(os.environ,GH_TOKEN=self.token) if self.token else None)
            except subprocess.TimeoutExpired:
                if method!='GET' or attempt==attempts-1:
                    raise RuntimeError(f'GitHub API {method} {path}: timed out') from None
                time.sleep(min(30,2**attempt))
                continue
            if not result.returncode:
                return result.stdout if raw else json.loads(result.stdout or b'{}')
            error=result.stderr.decode(errors='replace').lower()
            transient=any(marker in error for marker in (
                'rate limit','http 429','http 500','http 502','http 503','http 504',
                'connection reset','i/o timeout','tls handshake timeout','unexpected eof',
                'connection timed out','temporary failure in name resolution'))
            # A rate-limit rejection did not perform the write; other write
            # failures may have committed and must not be replayed.
            rejected_limit='http 429' in error or ('http 403' in error and 'rate limit' in error)
            retryable=transient if method=='GET' else rejected_limit
            if not retryable or attempt==attempts-1:
                raise RuntimeError(f'GitHub API {method} {path}: exit {result.returncode}')
            time.sleep(60 if 'rate limit' in error or '429' in error else min(30,2**attempt))

    def download(self,path,destination,size,digest=None):
        """Download large artifacts in up to eight resumable, disk-backed parts."""
        if size<=0:raise ValueError('invalid artifact size')
        if digest and not re.fullmatch(r'sha256:[0-9a-fA-F]{64}',digest):
            raise ValueError('unsupported artifact checksum')
        token=self.token or os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
        if not token:
            auth=subprocess.run(['gh','auth','token'],capture_output=True,text=True,timeout=60)
            if auth.returncode:raise RuntimeError('Cannot obtain artifact download credentials')
            token=auth.stdout.strip()
        url=path if path.startswith(('http://','https://')) else 'https://api.github.com/'+path
        deadline=time.monotonic()+3600
        workers=min(8,max(1,size//MIN_DOWNLOAD_PART_BYTES))
        destination=Path(destination)
        # Scratch files live beside the target for atomic publication after verification.
        with tempfile.TemporaryDirectory(dir=destination.parent,prefix='.artifact-') as tmp:
            parts=download_parts(url,token,Path(tmp),size,workers,deadline)
            assembled=Path(tmp)/'complete.zip'
            checksum=hashlib.sha256()
            with assembled.open('wb') as out:
                for part in parts:
                    with part.open('rb') as source:
                        while chunk:=source.read(1024*1024):
                            download_timeout(deadline)
                            checksum.update(chunk)
                            out.write(chunk)
            if digest and 'sha256:'+checksum.hexdigest()!=digest.lower():
                raise ValueError('artifact checksum mismatch')
            assembled.replace(destination)

    def pages(self,path,key):
        records=[]
        for page in range(1,1001):
            data=self.request(path+('&' if '?' in path else '?')+f'per_page=100&page={page}')
            batch=data[key] if key else data
            records.extend(batch)
            if len(batch)<100:return records
        raise RuntimeError('GitHub pagination limit exceeded')
    def artifacts(self,run_id):
        return self.pages(f'repos/{self.repository}/actions/runs/{int(run_id)}/artifacts','artifacts')
    def json_artifact(self,run_id,name,filename):
        artifact=select_artifact(self.artifacts(run_id),name)
        raw=self.request(f"repos/{self.repository}/actions/artifacts/{artifact['id']}/zip",raw=True)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            return json.loads(archive.read(filename))

def select_artifact(records,name):
    matches=[r for r in records if r['name']==name and not r.get('expired',False)]
    if len(matches)!=1:raise ValueError(f'expected one live artifact named {name}, found {len(matches)}')
    return matches[0]

def verify_binding(binding,context):
    for key in ('repository','sha','trigger_id','trigger_attempt'):
        if binding.get(key)!=context.get(key):raise ValueError('producer binding mismatch: '+key)

def resolve_producer(context,api):
    checks=api.pages(f"repos/{context['repository']}/commits/{context['sha']}/check-runs?filter=all",'check_runs')
    external=f"ci-tier-origin:{context['trigger_id']}:{context['trigger_attempt']}"
    matches=[c for c in checks if c.get('external_id')==external]
    if len(matches)!=1:raise ValueError('missing or ambiguous build registration for trigger execution')
    binding=json.loads(matches[0]['output']['text'])
    verify_binding(binding,context)
    return binding

def load_manifest(producer,api):
    eid='t{trigger_id}-a{trigger_attempt}-b{build_id}-a{build_attempt}'.format(**producer)
    plan=api.json_artifact(producer['build_id'],'ci-manifest-'+eid,'manifest.json')
    validate_manifest(plan);verify_binding(plan,producer)
    if plan['execution_id']!=eid:raise ValueError('producer attempt mismatch')
    return plan

def validate_binary(tier,version):
    expected={'v30':(3,0),'v31':(3,1),'v40':(4,0)}[tier]
    if version_tuple(version)[:2]!=expected:raise ValueError('restored binary does not match requested product tier')

def safe_members(members):
    for member in members:
        path=PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or member.isdev() or member.isfifo():
            raise ValueError('unsafe handoff archive member: '+member.name)
        if member.issym() or member.islnk():
            link=PurePosixPath(member.linkname)
            # Symlinks are relative to their parent; hard links to the archive root.
            target=PurePosixPath(posixpath.normpath(str(path.parent/link if member.issym() else link)))
            if link.is_absolute() or '..' in target.parts:raise ValueError('unsafe handoff link')
            # The data filter additionally resolves chains through existing links.
    return members

def handoff_filter(member,dest_path):
    """tarfile's 'data' filter, working around CPython gh-107845 on older interpreters.

    Before 3.10.13/3.11.5 the data filter resolved a relative symlink target against the destination
    root instead of the link's own directory (ubuntu-22.04 runners ship Python 3.10.12). That both
    rejects legitimate in-tree links, e.g. test/afl_digest_test/c_tokenizer.h -> ../../include/c_tokenizer.h
    (LinkOutsideDestinationError), and accepts links that escape through a link extracted earlier,
    e.g. a/b/c/alias -> ../../.. then a/b/c/link -> alias/../outside. So every symlink gets the fixed
    interpreters' check: realpath() of the target taken from the link's directory, following links
    already extracted, must stay under the destination. A link the old filter rejected but that passes
    this check gets the rest of the data filter (modes, ownership, member type) through a copy with a
    harmless target, and its original target back.
    """
    if not member.issym():return tarfile.data_filter(member,dest_path)
    try:filtered=tarfile.data_filter(member,dest_path)
    except tarfile.LinkOutsideDestinationError:filtered=None
    root=os.path.realpath(dest_path)
    target=os.path.realpath(os.path.join(root,os.path.dirname(member.name),member.linkname))
    if os.path.commonpath([root,target])!=root:raise tarfile.LinkOutsideDestinationError(member,target)
    if filtered is None:
        filtered=tarfile.data_filter(member.replace(linkname='.',deep=False),dest_path).replace(linkname=member.linkname,deep=False)
    return filtered

def binary_version(root, binary='src/proxysql'):
    """Probe on the host, then in the build ABI, with bounded waits and cleanup."""
    root=Path(root).resolve()
    binary_path=(root/binary).resolve()
    try:
        result=subprocess.run([str(binary_path),'--version'],capture_output=True,text=True,timeout=300)
        if result.returncode==0:
            return result.stdout+result.stderr
        host_error=f'exit {result.returncode}: '+result.stdout+result.stderr
    except subprocess.TimeoutExpired as error:
        host_error=f'timed out after {error.timeout} seconds'
    except OSError as error:
        host_error=str(error)
    # Host probes historically accept absolute paths and external symlinks.
    # Only the fallback is constrained to the tree mounted into the container.
    try:
        relative=binary_path.relative_to(root)
    except ValueError:
        raise RuntimeError(f'ProxySQL version probe failed. Host: {host_error}\n'
                           f'Build container: binary {binary_path} is outside {root}') from None
    # Ubuntu 24 artifacts need their build ABI; consumers can run on Ubuntu 22.
    # Use the same packaging image as the unit runner if the host loader fails.
    container_name='ci-version-'+uuid.uuid4().hex
    try:
        result=subprocess.run(['docker','run','--rm','--name',container_name,'--network','none',
            '-v',str(root)+':/opt/proxysql:ro',
            '-e','LD_LIBRARY_PATH=/opt/proxysql/test/tap/tap:/opt/proxysql/test/tap/tap/_runtime_libs',
            'proxysql/packaging:build-ubuntu24-v4.0.0',str(Path('/opt/proxysql')/relative),'--version'],
            capture_output=True,text=True,timeout=300)
        if result.returncode==0:
            return result.stdout+result.stderr
        container_error=f'exit {result.returncode}: '+result.stdout+result.stderr
    except subprocess.TimeoutExpired as error:
        container_error=f'timed out after {error.timeout} seconds'
        # Killing the Docker CLI does not stop the container. Remove only this
        # probe's uniquely named container, with a separate bounded wait.
        try:
            cleanup=subprocess.run(['docker','rm','-f',container_name],
                                   capture_output=True,text=True,timeout=30)
            if cleanup.returncode:
                container_error+='; cleanup failed: '+cleanup.stdout+cleanup.stderr
        except (OSError, subprocess.TimeoutExpired) as cleanup_error:
            container_error+='; cleanup failed: '+str(cleanup_error)
    except OSError as error:
        container_error=str(error)
    raise RuntimeError(f'ProxySQL version probe failed. Host: {host_error}\nBuild container: {container_error}')


def restore_handoff(manifest,leg,destination,api):
    validate_manifest(manifest)
    expected=next(x for x in manifest['legs'] if x['tier']==leg['tier'])
    if leg['artifact_name']!=expected['artifact_name']:raise ValueError('wrong handoff identity')
    record=select_artifact(api.artifacts(manifest['build_id']),expected['artifact_name'])
    if expected.get('artifact_id') and record['id']!=expected['artifact_id']:raise ValueError('handoff artifact replaced')
    with tempfile.TemporaryDirectory() as tmp:
        downloaded=Path(tmp)/'handoff.zip'
        api.download(f"repos/{api.repository}/actions/artifacts/{record['id']}/zip",downloaded,record['size_in_bytes'],digest=record.get('digest'))
        with zipfile.ZipFile(downloaded) as archive:
            packed=Path(tmp)/'cache_full.tar.zst'
            with archive.open('cache_full.tar.zst') as source,packed.open('wb') as out:
                shutil.copyfileobj(source,out,1024*1024)
        downloaded.unlink()
        tarpath=Path(tmp)/'full.tar'
        with tarpath.open('wb') as out:subprocess.run(['zstd','-d','-c',str(packed)],stdout=out,check=True)
        destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
        with tarfile.open(tarpath) as archive:
            archive.extractall(destination,members=safe_members(archive.getmembers()),filter=handoff_filter)
    metadata=json.loads((destination/'src/ci-tier.json').read_text())
    for key,value in [('execution_id',manifest['execution_id']),('sha',manifest['sha']),('tier',leg['tier']),('mode',leg['mode'])]:
        if metadata.get(key)!=value:raise ValueError('restored metadata mismatch: '+key)
    validate_binary(leg['tier'],binary_version(destination))
