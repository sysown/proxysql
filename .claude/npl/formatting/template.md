# Template
Reusable template definitions for consistent output formatting.

## Syntax
`⌜🧱 <name>` ... `⌟`

## Purpose
Define reusable output format/template that can be applied across multiple contexts to ensure consistent formatting and structure.

## Usage
Templates are declared using the special section syntax with the 🧱 emoji prefix, followed by the template name. The template content is defined within the declaration boundaries.

## Examples
```example
⌜🧱 user-card
@with NPL@1.0
```template
<b>{user.name}</b>
<p>{user.bio}</p>
```
⌟
```

## Template Integration
Templates can be integrated into outputs using directive syntax:

```example
⟪⇐: user-template | with the data of each executive.⟫
```

## Parameters
- `name`: Unique identifier for the template
- Template content uses handlebar-like syntax for placeholders
- Optional NPL version specification with `@with NPL@version`

## Template Content Format
Templates support:
- Placeholder substitution using `{variable.path}`
- HTML-like formatting tags
- Conditional logic integration
- Data iteration patterns

## See Also
- `./special-section/named-template.md` - Named template declarations
- `./directive/⇐.md` - Template integration directive
- `./instructing/handlebars.md` - Handlebar syntax patterns