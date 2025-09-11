# Note and Comment Blocks
Code fence for including explanatory notes, comments, and additional context.

## Syntax
```note
[note content]
```

## Purpose
The `note` fence provides a way to include explanatory comments, clarifications, warnings, or additional context within prompts without directly affecting the generated output. These blocks serve as documentation and guidance for prompt understanding.

## Usage
Use note blocks when you need to:
- Provide clarifying comments about prompt structure
- Add warnings or important reminders
- Include implementation notes or considerations
- Document intent behind specific prompt elements
- Explain complex relationships between components

## Examples

### Basic Note Block
```note
The attention marker should be used sparingly to maintain its impact.
```

### Implementation Note
```note
This template uses handlebar syntax for iteration. If the agent doesn't recognize {{foreach}}, load ./npl/instructing/handlebars.md for detailed syntax support.
```

### Warning Note
```note
🎯 IMPORTANT: Always validate user inputs before processing to prevent security vulnerabilities.
```

### Multi-line Explanatory Note
```note
The following format specification uses size qualifiers:
- `p` for paragraphs
- `s` for sentences  
- `i` for list items

These help control the length and structure of generated content.
```

### Context Note
```note
This agent definition extends the base NPL@0.5 framework with specialized cat fact generation capabilities. The format block ensures consistent output structure across all responses.
```

## In NPL Source
From NPL@0.5 base.md, note blocks are described as special code sections that "provide additional information within the prompt" and ensure "the note's context and significance are understood."

The NPL definition emphasizes that notes help clarify expectations and provide contextual guidance for better prompt interpretation.

## Integration with NPL
Note blocks are commonly used in:
- Agent definitions to explain behavioral choices
- Syntax documentation to clarify usage patterns
- Template specifications to document structure decisions
- Complex prompt constructs to explain relationships
- Format blocks to clarify expected output patterns

## Note Types and Conventions

### Warning Notes
Use attention markers for critical information:
```note
🎯 This directive requires specific formatting - ensure exact syntax match.
```

### Implementation Notes
For technical considerations:
```note
If handlebars aren't recognized, the agent should fall back to simple placeholder substitution.
```

### Context Notes
For explaining relationships:
```note
This format builds on the user-template defined earlier in the prompt block.
```

### Reference Notes
For additional resources:
```note
See ./npl/syntax/qualifier.md for complete qualifier syntax reference.
```

## Best Practices
- Keep notes concise but informative
- Use attention markers (🎯) for critical information
- Reference related documentation when helpful
- Explain complex or non-obvious relationships
- Include implementation considerations when relevant

## See Also
- `./.claude/npl/fences.md` - Overview of all fence types
- `./.claude/npl/syntax/attention.md` - Attention marker usage
- `./.claude/npl/fences/example.md` - Example block formatting
- `./.claude/npl/instructing.md` - Instruction pattern documentation