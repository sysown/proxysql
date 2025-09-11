# Template Fence
Template definition blocks for creating reusable output formats and structures.

## Syntax
```template
<template content with placeholders>
```

## Purpose
Template fences define reusable output formats that can be applied consistently across different contexts. They support placeholder substitution, conditional logic, and structured formatting patterns.

## Usage
Use template fences when defining:
- Reusable output patterns
- Consistent formatting structures
- Data presentation templates
- Response format specifications

## Examples

### User Profile Template
```example
```template
# {user.name}
**Role**: {user.role}
**Email**: {user.email}
**Bio**: {user.bio}

## Recent Activity
{foreach user.activities as activity}
- {activity.date}: {activity.description}
{/foreach}
```
```

### Data Table Template
```example
```template
| Name | Value | Status |
|------|-------|--------|
{foreach data as item}
| {item.name} | {item.value} | {item.status} |
{/foreach}
```
```

### Conditional Content Template
```example
```template
## Report Summary
**Date**: {report.date}
**Status**: {report.status}

{if report.errors}
### Errors Found
{foreach report.errors as error}
- **{error.level}**: {error.message}
{/foreach}
{else}
✅ No errors detected
{/if}

{if report.warnings}
### Warnings
{foreach report.warnings as warning}
- ⚠️ {warning.message}
{/foreach}
{/if}
```
```

### JSON Response Template
```example
```template
{
  "status": "{response.status}",
  "timestamp": "{response.timestamp}",
  "data": {
    {foreach response.items as item}
    "{item.key}": "{item.value}"{if not @last},{/if}
    {/foreach}
  }
}
```
```

## Template Variables
- `{variable.name}` - Simple variable substitution
- `{variable.name|qualifier}` - Qualified variable with formatting
- `{foreach collection as item}...{/foreach}` - Iteration over collections
- `{if condition}...{else}...{/if}` - Conditional content inclusion
- `{@last}`, `{@first}`, `{@index}` - Loop context variables

## Parameters
Templates support various control parameters:
- Variable substitution patterns
- Loop control structures  
- Conditional logic operators
- Formatting qualifiers
- Context-aware variables

## See Also
- `./../../formatting/template.md` - Reusable template definitions
- `./../../instructing/handlebars.md` - Template control flow syntax
- `./../special-section/named-template.md` - Named template definitions
- `./../../syntax/qualifier.md` - Qualifier syntax for template variables