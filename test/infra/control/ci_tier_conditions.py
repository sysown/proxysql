"""Evaluate the condition subset used by tier routes; reject unknown expressions.

This is a structural CI contract checker, not a general Actions interpreter.
Contexts describe a successful, trusted automatic cascade. Both TAP modes must
have an executable route. New expression constructs need explicit support/tests.
"""
import ast
import json
import re

TOKEN = re.compile(r"'(?:''|[^'])*'|[A-Za-z_][A-Za-z0-9_.*-]*|&&|\|\||!=|==|!|\d+|[(),\[\]]")
FUNCTIONS = {
    'success': lambda: True,
    'always': lambda: True,
    'failure': lambda: False,
    'cancelled': lambda: False,
    'fromjson': json.loads,
    'startswith': lambda value, prefix: value.lower().startswith(prefix.lower()),
    'contains': lambda value, part: part.lower() in value.lower() if isinstance(value, str) else part in value,
}


def evaluate(node, functions=FUNCTIONS):
    """Evaluate whitelisted AST nodes without executing workflow-supplied code."""
    if isinstance(node, ast.List):
        return [evaluate(item, functions) for item in node.elts]
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not evaluate(node.operand, functions)
    if isinstance(node, ast.BoolOp):
        value = None
        for item in node.values:
            value = evaluate(item, functions)
            if isinstance(node.op, ast.And) and not value:
                return value
            if isinstance(node.op, ast.Or) and value:
                return value
        return value
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, right = evaluate(node.left, functions), evaluate(node.comparators[0], functions)
        if isinstance(left, str) and isinstance(right, str):
            left, right = left.lower(), right.lower()
        if isinstance(node.ops[0], ast.Eq):
            return left == right
        if isinstance(node.ops[0], ast.NotEq):
            return left != right
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.keywords:
        return functions[node.func.id](*(evaluate(arg, functions) for arg in node.args))
    if isinstance(node, ast.Subscript):
        value, key = evaluate(node.value, functions), evaluate(node.slice, functions)
        try:
            return value[key]
        except (KeyError, IndexError):
            return None
    raise ValueError('unsupported condition syntax')


def condition_allows(condition, tier, mode, inputs=None, job='tests', needs_results=None, event_context=None):
    """Check a gate for one selected tier/mode, failing closed on unknown context."""
    if condition is None:
        condition = True
    if isinstance(condition, bool):
        condition = 'true' if condition else 'false'
    expression = str(condition).strip()
    if expression.startswith('${{') and expression.endswith('}}'):
        expression = expression[3:-2].strip()
    context = {
        'matrix.tier': tier, 'matrix.mode': mode, 'matrix.coverage': True,
        'inputs.trusted': True,
        'github.event.workflow_run': True,
        'github.event.workflow_run.conclusion': 'success',
        'github.event.workflow_run.display_title': 'feature/ci-validation CI-trigger abc123',
        'github.event.workflow_run.head_branch': 'feature/ci-validation',
        'github.ref_name': 'feature/ci-validation',
        'github.event.workflow_run.head_repository.full_name': 'sysown/proxysql',
        'github.repository': 'sysown/proxysql',
        'needs.tier-context.result': 'success',
        'needs.tier-context.outputs.matrices': json.dumps({job: [{'tier': tier}]}),
    }
    if needs_results is not None:
        context.pop('needs.tier-context.result', None)
        context.update({'needs.' + key + '.result': value for key, value in needs_results.items()})
    context.update({'inputs.' + key: value for key, value in (inputs or {}).items()})
    context.update(event_context or {})
    translated = []
    offset = 0
    for match in TOKEN.finditer(expression):
        if expression[offset:match.start()].strip():
            raise ValueError('unsupported condition token')
        token = match[0]
        offset = match.end()
        if token.startswith("'"):
            translated.append(repr(token[1:-1].replace("''", "'")))
        elif token in context:
            translated.append(repr(context[token]))
        elif token.lower() in ('true', 'false', 'null'):
            translated.append({'true': 'True', 'false': 'False', 'null': 'None'}[token.lower()])
        elif token.lower() in FUNCTIONS:
            translated.append(token.lower())
        elif token in ('&&', '||', '!'):
            translated.append({'&&': 'and', '||': 'or', '!': 'not'}[token])
        elif token[0].isalpha() or token.startswith('_'):
            raise ValueError('unknown condition context: ' + token)
        else:
            translated.append(token)
    if expression[offset:].strip() or not translated:
        raise ValueError('unsupported condition token')
    try:
        tree = ast.parse(' '.join(translated), mode='eval').body
        # Actions binds ! above equality; Python binds not below equality.
        # Reject ambiguous negated comparisons, while allowing independent
        # terms such as !cancelled() && matrix.tier != 'v40'.
        if any(isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)
               and isinstance(node.operand, ast.Compare) for node in ast.walk(tree)):
            raise ValueError('negation before comparison is unsupported; use an explicit inverse comparison')
        functions = dict(FUNCTIONS)
        if needs_results is not None:
            # Model job gating in a successful, non-cancelled cascade. A
            # skipped prerequisite is not a failure. Runtime failures are
            # outside this structural check.
            successful = all(result == 'success' for result in needs_results.values())
            functions['success'] = lambda: successful
            has_status = any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                             and node.func.id in ('success', 'failure', 'cancelled', 'always')
                             for node in ast.walk(tree))
            if not has_status and not successful:
                return False
        return bool(evaluate(tree, functions))
    except (SyntaxError, TypeError, KeyError, AttributeError) as error:
        raise ValueError('unsupported condition expression') from error
