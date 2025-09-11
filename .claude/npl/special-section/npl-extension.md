# NPL Extension Declaration
Framework extension syntax for building upon and enhancing existing NPL guidelines.

## Syntax
`⌜extend:NPL@version⌝[...modifications...]⌞extend:NPL@version⌟`

## Purpose
To build upon and enhance existing NPL guidelines and rules for more specificity or breadth without creating entirely new framework versions. Extensions allow modular addition of capabilities while maintaining compatibility with base framework specifications.

## Usage
Use NPL extensions when you need to:
- Add specialized syntax elements to existing framework versions
- Define domain-specific conventions that extend base NPL
- Create reusable enhancement modules that can be applied selectively
- Maintain backward compatibility while adding new features

## Examples

```example
⌜extend:NPL@1.0⌝
Additional syntax for mathematical notation support:

**math-inline**: `$expression$` - Inline mathematical expressions
**math-block**: `$$expression$$` - Block mathematical expressions

Example usage:
The quadratic formula is $x = \frac{-b \pm \sqrt{b^2 - 4ac}}{2a}$

⌞extend:NPL@1.0⌟
```

```example
⌜extend:NPL@1.0⌝
Domain-specific extension for API documentation:

**endpoint**: `@{method} /path` - API endpoint declaration
**status-code**: `{code}: description` - HTTP status code documentation

Example usage:
@{GET} /users/{id}
{200}: User found successfully
{404}: User not found

⌞extend:NPL@1.0⌟
```

## Structure Requirements
- Must reference a specific NPL version using `extend:NPL@version`
- Opening and closing delimiters must match the version specification
- Extensions should be self-contained and clearly document added functionality
- Should not conflict with existing NPL syntax elements

## Inheritance Behavior
- Extensions inherit all rules from the base NPL version
- New syntax elements take precedence over base framework defaults
- Extensions can be layered (an extension can extend another extension)
- Conflicts between extensions should be resolved through explicit precedence rules

## See Also
- `.claude/npl/declarations.md` - Base framework version boundaries
- `.claude/npl/special-section.md` - Overview of special prompt sections