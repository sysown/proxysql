# Input Syntax
Input format specifications for structured data entry and parameter definition.

## Syntax
`input-syntax` fence blocks or inline specifications

## Purpose
Define the expected structure and format for input data, parameters, and user-provided content within prompts and agent interactions.

## Usage
Input syntax specifications help agents understand the expected format of data they will receive, enabling proper parsing and processing.

## Examples

### Fence Block Format
```example
```input-syntax
<user.name>: string
<user.age>: number|optional
<preferences>: array|comma-separated
```
```

### Inline Specifications
```example
Expected input: `{user.name | string}`, `{preferences | list of items}`
```

### Handlebar-Style Input
```example
```input-syntax
{{user.profile}}
  name: <string>
  email: <email-format>
  preferences: [<item>, <item>, ...]
{{/user.profile}}
```
```

## Input Types
Common input type indicators:
- `string` - Text input
- `number` - Numeric values
- `email-format` - Email addresses
- `array` - List of items
- `optional` - Non-required field
- `comma-separated` - List format
- `json` - JSON structured data

## Qualifiers
Input specifications support qualifiers:
- `|optional` - Field is not required
- `|required` - Field must be provided
- `|default:value` - Default value if not specified
- `|format:pattern` - Expected format pattern

## Validation Patterns
```example
```input-syntax
<username>: string|pattern:^[a-zA-Z0-9_]+$
<password>: string|min-length:8
<age>: number|range:18-100
```
```

## See Also
- `./output-syntax.md` - Output format specifications
- `./input-example.md` - Input example structures
- `../syntax/placeholder.md` - Placeholder syntax patterns