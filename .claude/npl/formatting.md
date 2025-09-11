# Output Formatting Patterns and Templates
Comprehensive overview of NPL formatting conventions for structured output generation and template systems.

⌜npl-formatting|overview|NPL@1.0⌝

## Purpose
NPL formatting patterns provide structured approaches to defining input/output shapes, examples, and reusable templates that control how agents generate responses. These patterns ensure consistency across different output types and enable precise specification of desired formats.

## Core Formatting Types

### Template Definition
Reusable output structures using handlebar-style syntax for dynamic content generation.

```syntax
⌜🧱 template-name⌝
@with NPL@1.0
```template
<template structure with placeholders>
```
⌞🧱 template-name⌟
```

**Purpose**: Define once, use multiple times for consistent output formatting across different contexts.

### Input/Output Specification
Format blocks that define expected structure for data exchange between user and agent.

**Input Format**
```syntax
```input-syntax
<expected input structure>
```
```

**Output Format** 
```syntax
```output-syntax
<desired output structure>
```
```

**Combined Format**
```syntax
```format
<complete input/output specification>
```
```

### Example Structures
Demonstration blocks showing concrete instances of formatting patterns in action.

**Input Examples**
```syntax
```input-example
<actual input sample>
```
```

**Output Examples**
```syntax
```output-example  
<actual output sample>
```
```

**General Examples**
```syntax
```example
<sample input/output pair>
```
```

## Common Formatting Patterns

### Structured Data Layout
Using placeholders and qualifiers to define data insertion points:

```example
Hello <user.name>,
Did you know [...|funny factoid].

Have a great day!
```

### Conditional Formatting
Template control structures for dynamic content inclusion:

```example
{{if user.role == 'admin'}}
Welcome to the admin panel!
{{else}}
Welcome to the user dashboard!
{{/if}}
```

### Iterative Content Generation
Loop structures for repeated pattern application:

```example
# User List
{{foreach users as user}}
## <user.name>
Role: <user.role>
Bio: [...2-3s|user description]
{{/foreach}}
```

### Template Integration
Embedding predefined templates within larger output structures:

```example
Business Profile:
⟪⇆: user-template | with executive data⟫
```

## Size and Content Qualifiers

### Size Indicators
Specify content volume using standardized size markers:

- `p`: paragraphs
- `pg`: pages  
- `l`: lines
- `s`: sentences
- `w`: words
- `i`: items
- `r`: rows
- `t`: tokens

**Usage**: `[...3-5w]` for 3-5 words, `[...2p]` for 2 paragraphs

### Content Qualifiers
Modify placeholder behavior with specific instructions:

```syntax
<term|qualifier>
[...|specific instructions]
{data|transformation rules}
```

## Advanced Formatting Features

### Table Formatting
Structured tabular output with alignment specifications:

```syntax
⟪📅: (column alignments and labels) | content description⟫
```

**Example Output**:
```
| Name | Score | Status |
|:-----|------:|:------:|  
| Alice|    95 |  Pass  |
| Bob  |    87 |  Pass  |
```

### Template Variables
Dynamic content injection using various placeholder styles:

- **Simple**: `<variable>`
- **Qualified**: `<variable|qualifier>`  
- **Sized**: `<<size>:variable>`
- **Conditional**: `{variable|default_value}`

### Content Omission
Structured approaches to content brevity:

**Named Clipping**: `[...#unique-name]` for user-requestable continuation
**Simple Omission**: `[___]` for expected but omitted content

## Formatting Control Mechanisms

### Output Structure Definition
Pre-defining the shape and organization of agent responses:

```format
Header: <title>
🎯 Key Point: [...1s|main message]

## Details  
[...2-3p|supporting information]

## References
[...3-5i|related links or sources]
```

### Response Mode Integration
Formatting patterns that work with prefix directives:

```example
📄➤ Summarize this document:
```format-summary
# <document.title>

**Overview**: [...2-3s|key summary]

**Main Points**:
- [...|point 1]
- [...|point 2]  
- [...|point 3]

**Conclusion**: [...1s|final takeaway]
```
```

### Multi-Format Support
Templates that adapt to different output requirements:

```template
{{if output_format == 'brief'}}
<title>: [...1s|summary]
{{else}}
# <title>
[...2-3p|detailed explanation]

## Key Points
[...5-7i|bullet list]
{{/if}}
```

## Template Reuse and Inheritance

### Named Template Declaration
Creating reusable formatting components:

```syntax
⌜🧱 user-card⌝
@with NPL@1.0
```template
**<user.name>** (<user.role>)
Contact: <user.email>
Bio: [...2s|user background]
```
⌞🧱 user-card⌟
```

### Template Application
Using predefined templates within larger contexts:

```syntax
# Team Directory
{{foreach team_members as member}}
⟪⇆: user-card | with member data⟫
﹍
{{/foreach}}
```

## Best Practices

### Consistency Guidelines
- Use standardized size indicators across all templates
- Apply consistent placeholder naming conventions  
- Maintain uniform formatting styles within template families

### Modularity Principles
- Create reusable templates for common output patterns
- Design templates that work across different content types
- Enable template composition for complex output structures  

### User Experience Optimization
- Provide clear examples alongside format specifications
- Use meaningful placeholder names that indicate expected content
- Include fallback patterns for edge cases

## See Also
- `./.claude/npl/fences.md` - Complete fence type reference including format-specific fences
- `./.claude/npl/syntax/placeholder.md` - Deep-dive into placeholder conventions
- `./.claude/npl/directive.md` - Specialized formatting directives
- `./.claude/npl/special-section/named-template.md` - Advanced template definition patterns  
- `./.claude/npl/instructing/handlebars.md` - Template control flow syntax
- `./.claude/npl/formatting/template.md` - Detailed template construction guide
- `./.claude/npl/formatting/input-syntax.md` - Input format specifications
- `./.claude/npl/formatting/output-syntax.md` - Output format specifications

⌞npl-formatting⌟