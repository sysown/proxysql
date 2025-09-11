# Literal Output
Exact text reproduction syntax that ensures specified text is output exactly as provided without modification, interpretation, or formatting changes.

## Syntax
`{~l|Keep it simple, stupid.}` - Literal quote syntax  
`` `{~l|literal text}` `` - Literal text with backtick wrapping

## Purpose
Literal output syntax guarantees that specific text passages are reproduced exactly as written, preserving original formatting, punctuation, spacing, and character sequences. This is essential for maintaining the integrity of quotes, code snippets, legal text, or any content where precision is critical.

## Usage
Use literal output syntax when you need to:
- Preserve exact quotations without alteration
- Maintain specific formatting or spacing requirements
- Ensure technical syntax is not interpreted or modified
- Output legal, contractual, or formal text with precision
- Reproduce historical or cultural text with authenticity

## Examples

### Famous Quote Preservation
```example
When quoting Shakespeare, use `{~l|To be, or not to be}` exactly.
```
Output: "To be, or not to be" (exactly as specified, without interpretation)

### Technical Command Preservation
```example
The exact command is `{~l|sudo apt-get update && sudo apt-get upgrade}`.
```
Ensures the command syntax is not modified or reformatted.

### Code Syntax Preservation
```example
The function signature must be `{~l|function calculateTotal(items: Item[]): number}`.
```
Preserves exact TypeScript syntax without modification.

### Legal Text Preservation
```example
The contract clause states: `{~l|Party A shall be liable for any damages exceeding $10,000.00 USD}`.
```
Maintains exact legal language and formatting.

### Multi-line Literal Text
```example
The error message should display:
`{~l|Error 404: Resource not found.
Please check the URL and try again.
Contact support if the problem persists.}`
```
Preserves exact line breaks and formatting.

### Special Character Preservation
```example
The regex pattern is `{~l|^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$}`.
```
Ensures special regex characters are not interpreted.

## Key Features

### Exact Character Reproduction
- Preserves all whitespace, including spaces, tabs, and line breaks
- Maintains special characters without escape sequence interpretation  
- Keeps original punctuation and formatting intact

### No Processing or Interpretation
- Content is not parsed for markdown, HTML, or other markup
- Variables or placeholders within literal text are not processed
- No automatic formatting or style application occurs

### Context Independence  
- Literal content is isolated from surrounding text processing
- Template engines or formatting rules do not affect literal sections
- Content remains unchanged regardless of output format requirements

## Advanced Usage

### Nested Quotes
```example
The response should include `{~l|The user said: "I need help with this."}`.
```
Preserves nested quotation marks exactly.

### Configuration Examples
```example
Add to config file: `{~l|database.host=localhost:5432
database.user=admin
database.password=secure123}`.
```
Maintains exact configuration file format.

### Mathematical Expressions
```example
The formula is `{~l|E = mc² + ∫(F·dx) from a to b}`.
```
Preserves mathematical notation without interpretation.

## Best Practices
- Use literal syntax for any text that must remain unchanged
- Apply to quotes, commands, code, formulas, and formal documents
- Consider using for user-generated content that needs exact reproduction
- Test literal output to ensure no unintended processing occurs

## See Also
- `./highlight.md` - Term emphasis while preserving content
- `./value-placeholder.md` - Dynamic content injection (opposite of literal)
- `./../../fences/example.md` - Example blocks with controlled formatting