"""Evaluate the condition subset used by tier routes; reject unknown expressions.

This is a structural CI contract checker, not a general Actions interpreter.
Contexts describe a successful, trusted automatic cascade. Both TAP modes must
have an executable route. New expression constructs need explicit support/tests.
"""
import ast
import json
import re

TOKEN = re.compile(r"'(?:''|[^'])*'|[A-Za-z_][A-Za-z0-9_.-]*|&&|\|\||!=|==|!|\d+|[(),\[\]]")
FUNCTIONS = {
    'success': lambda: True,
    'always': lambda: True,
    'failure': lambda: False,
    'cancelled': lambda: False,
    'fromjson': json.loads,
    'startswith': lambda value, prefix: value.lower().startswith(prefix.lower()),
    'contains': lambda value, part: part.lower() in value.lower() if isinstance(value, str) else part in value,
}


def evaluate(node):
    """Evaluate whitelisted AST nodes without executing workflow-supplied code."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not evaluate(node.operand)
    if isinstance(node, ast.BoolOp):
        value = None
        for item in node.values:
            value = evaluate(item)
            if isinstance(node.op, ast.And) and not value:
                return value
            if isinstance(node.op, ast.Or) and value:
                return value
        return value
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, right = evaluate(node.left), evaluate(node.comparators[0])
        if isinstance(left, str) and isinstance(right, str):
            left, right = left.lower(), right.lower()
        if isinstance(node.ops[0], ast.Eq):
            return left == right
        if isinstance(node.ops[0], ast.NotEq):
            return left != right
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.keywords:
        return FUNCTIONS[node.func.id](*(evaluate(arg) for arg in node.args))
    if isinstance(node, ast.Subscript):
        value, key = evaluate(node.value), evaluate(node.slice)
        try:
            return value[key]
        except (KeyError, IndexError):
            return None
    raise ValueError('unsupported condition syntax')


def condition_allows(condition, tier, mode, inputs=None, job='tests'):
    """Check a gate for one selected tier/mode, failing closed on unknown context."""
    if isinstance(condition, bool):
        return condition
    if condition is None:
        return True
    expression = str(condition).strip()
    if expression.startswith('${{') and expression.endswith('}}'):
        expression = expression[3:-2].strip()
    context = {
        'matrix.tier': tier, 'matrix.mode': mode, 'matrix.coverage': tier == 'v40',
        'inputs.trusted': True,
        'github.event.workflow_run': True,
        'github.event.workflow_run.conclusion': 'success',
        'github.event.workflow_run.head_branch': 'feature/ci-validation',
        'github.ref_name': 'feature/ci-validation',
        'github.event.workflow_run.head_repository.full_name': 'sysown/proxysql',
        'github.repository': 'sysown/proxysql',
        'needs.tier-context.result': 'success',
        'needs.tier-context.outputs.matrices': json.dumps({job: [{'tier': tier}]}),
    }
    context.update({'inputs.' + key: value for key, value in (inputs or {}).items()})
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
        return bool(evaluate(ast.parse(' '.join(translated), mode='eval').body))
    except (SyntaxError, TypeError, KeyError, AttributeError) as error:
        raise ValueError('unsupported condition expression') from error
