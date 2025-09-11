# Syntax Definition Block Structure
Code fence for defining and documenting syntax patterns and their usage rules.

## Syntax
```syntax
[syntax definition content]
```

## Purpose
The `syntax` fence is used to formally define syntax patterns, grammar rules, and structural conventions within NPL. It provides a standardized way to document how specific syntax elements should be constructed and used.

## Usage
Use syntax blocks when you need to:
- Define formal syntax patterns
- Document grammar rules and conventions
- Specify structural requirements for elements
- Provide canonical syntax reference

## Examples

### Basic Syntax Definition
```syntax
`highlight`: `term` - Emphasize key concepts
```

### Complex Syntax Pattern
```syntax
placeholder: `<term>`, `{term}`, `<<qualifier>:term>` - Expected input/output locations
qualifier: `term|qualifier` - Can be used with most syntax elements
```

### Multi-element Syntax Block
```syntax
Agent Declaration:
⌜agent-name|type|NPL@version⌝
# Agent Name
[...definition content...]
⌞agent-name⌟
```

### Syntax with Parameters
```syntax
Table Directive:
⟪📅: (column alignments and labels) | content description⟫

Parameters:
- column alignments: left, right, center alignments for each column
- labels: custom header names for columns
- content description: what data should populate the table
```

## In NPL Source
The syntax fence appears in NPL@0.5 documentation within YAML syntax-elements definitions and is used to establish formal patterns for various prompt constructs.

From agent.md NPL sources, syntax blocks use structured formatting:
```syntax
```nlp-intent
intent:
  overview: <brief description of intent>
  steps:
    - <step 1>
    - <step 2>
    - <step 3>
```

## Integration with NPL
In NPL, syntax blocks are essential for:
- Documenting core syntax elements in `./npl/syntax/`
- Defining agent declaration patterns
- Specifying directive syntax in `./npl/directive/`
- Establishing prefix syntax in `./npl/prefix/`
- Creating format specifications

## Formatting Conventions
Within syntax blocks:
- Use backticks for literal syntax elements
- Use angle brackets `<>` for required parameters
- Use square brackets `[]` for optional elements
- Use pipe `|` for alternatives or qualifiers
- Use ellipsis `...` for extensible patterns

## See Also
- `./.claude/npl/fences.md` - Overview of all fence types
- `./.claude/npl/fences/example.md` - Example block usage
- `./.claude/npl/fences/format.md` - Format specification blocks
- `./.claude/npl/syntax.md` - Core syntax elements overview