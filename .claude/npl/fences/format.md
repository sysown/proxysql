# Format Specification Blocks
Code fence for defining expected output structures and template patterns.

## Syntax
```format
[format specification content]
```

## Purpose
The `format` fence specifies the exact structure and layout of expected output. It defines template patterns, data organization, and formatting requirements that agents should follow when generating responses.

## Usage
Use format blocks when you need to:
- Define expected output structure and layout
- Specify template patterns for consistent formatting
- Document data organization requirements
- Establish formatting standards for agent responses

## Examples

### Basic Format Specification
```format
Hello <user.name>,
Did you know [...|funny factoid].

Have a great day!
```

### Complex Format with Handlebars
```format
date: <current date|Y-M-D format>
🙋cat-facts: [...1s|summarize request as statement]

```catfact
[...1-2p|a cat fact]
```

# Cat Breeds
{{foreach as breed| from 5 random cat breeds}}
## {{breed.name}}
[...2-3s|breed description]

history: [...3-4p|breed history]
also-known-as: [...2-4i|comma separated list alt breed names]
{{/foreach}}
```

### Table Format Specification
```format
| #    | Prime |     English     |
| :--- | ----: | :-------------: |
| 1    |     2 |       Two       |
| 2    |     3 |      Three      |
| 3    |     5 |       Five      |
[...additional rows...]
```

### Template Integration Format
```format
Business Name: <business.name>
About the Business: <business.about>

## Executives
{foreach business.executives as executive}
- Name: <executive.name>
- Role: <executive.role>
- Bio: <executive.bio>
⟪⇐: user-template | with the data of each executive⟫
{/foreach}
```

## In NPL Source
From NPL@0.5 agent.md, format blocks use structured YAML-like syntax:

> Chain of Thought format ensures "clarity and allows for the analysis of the problem-solving process"

Example from NPL source:
```format
<nlp-cot>
thought_process:
  - thought: "Initial thought about the problem."
    understanding: "Understanding of the problem."
    theory_of_mind: "Insight into the question's intent."
</nlp-cot>
```

## Integration with NPL
Format blocks are essential for:
- Agent response templates in `./npl/special-section/agent.md`
- Output specifications in `./npl/formatting/`
- Template definitions in `./npl/fences/template.md`
- Structured data requirements in directive specifications

## Format Elements
Common format elements include:
- **Placeholders**: `<term>`, `{term}` for dynamic content
- **In-fill areas**: `[...]` for generated content with size qualifiers
- **Handlebars**: `{{foreach}}`, `{{if}}` for control structures
- **Directives**: `⟪emoji: instructions⟫` for special processing
- **Literal text**: Exact text that must appear in output

## Size Qualifiers in Formats
- `p`: paragraphs (e.g., `[...1-2p]`)
- `s`: sentences (e.g., `[...2-3s]`)
- `w`: words (e.g., `[...3-5w]`)
- `l`: lines (e.g., `[...5l]`)
- `i`: items (e.g., `[...2-4i]`)

## See Also
- `./.claude/npl/fences.md` - Overview of all fence types
- `./.claude/npl/fences/template.md` - Template definition blocks
- `./.claude/npl/formatting.md` - Output formatting overview
- `./.claude/npl/syntax/in-fill-size.md` - Size qualifier specifications