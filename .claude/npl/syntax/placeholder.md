# Placeholder Syntax
Input/output placeholder conventions for indicating expected content locations in prompts and templates.

## Syntax
- `<term>` - Basic placeholder
- `{term}` - Alternative placeholder format  
- `<<qualifier>:term>` - Qualified placeholder
- `⟪term⟫` - Directive placeholder for content injection

## Purpose
Mark locations where specific content should be inserted, either by users providing input or by agents generating output. Establishes clear expectations for dynamic content replacement.

## Usage
Use placeholders to:
- Indicate where user input should be provided
- Mark locations for generated content insertion
- Define template variables and substitution points
- Specify dynamic content areas in output formats

## Placeholder Types

### Basic Placeholders
- `<term>` - Standard placeholder for any content type
- `{term}` - Alternative syntax, often used in templates
- `{...}` - Generic content placeholder

### Qualified Placeholders  
- `<term|qualifier>` - Placeholder with additional instructions
- `{term|qualifier}` - Alternative qualified format
- `<<qualifier>:term>` - Directive-style qualified placeholder

### Special Formats
- `⟪input/output placeholder to be received or generated⟫` - Directive placeholder
- `<...>` - Generic angle bracket placeholder
- `{...}` - Generic curly brace placeholder

## Examples

```example
Hello {user.name}, welcome back to the system!
```
*Basic user name substitution*

```example
Select payment method: {payment methods|common for usa and india}
```
*Qualified placeholder specifying regional payment options*

```example
Generate a greeting for <user.name|format: last name, m.i, first name>
```
*Placeholder with specific formatting instructions*

```example
⟪input: user credentials⟫ → ⟪output: authentication token⟫
```
*Directive placeholders showing input/output flow*

```example
The event will be held on <event.date> at <event.location>.
```
*Multiple placeholders in a single sentence*

## Parameters
- `term`: The name or identifier of the content to be inserted
- `qualifier`: Additional instructions or constraints for the placeholder
- `format`: Specific formatting requirements for the content

## Advanced Patterns

### Nested Placeholders
```example
{user.profile.{selected_field}}
```

### Conditional Placeholders
```example
<greeting|if morning: "Good morning", else: "Hello">
```

### List Placeholders
```example
{shopping_list|items: 5-10, format: bullet points}
```

## See Also
- `./value-placeholder.md` - Dynamic content injection points
- `./qualifier.md` - Qualifier pipe syntax for modifications
- `../directive.md` - Specialized instruction patterns
- `../formatting/template.md` - Template-based placeholder usage