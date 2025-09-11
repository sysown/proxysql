# Fences
Code fence types and usage patterns for structured content containment and presentation in NPL.

## Syntax
````xpl
```<fence-type>
[...content]
```
````

## Purpose
Fences create specialized content blocks with specific formatting, processing, or display requirements. They structure and contain different types of content while providing semantic meaning about how that content should be interpreted or presented.

## Fence Types

### Content Fences

**example**
- Purpose: Demonstrate usage patterns or illustrate concepts
- Contains: Sample implementations, use cases, demonstrations
- Processing: Often displayed with special formatting or highlighting

**note** 
- Purpose: Provide additional information, clarifications, or warnings
- Contains: Supplementary explanations, caveats, important considerations
- Processing: Typically rendered with distinctive visual treatment

**diagram**
- Purpose: Visual representations of concepts, flows, or relationships  
- Contains: ASCII art, flowcharts, conceptual diagrams, system layouts
- Processing: May support enhanced rendering or diagram-specific formatting

### Structure Fences

**syntax**
- Purpose: Define formal syntax patterns and grammar rules
- Contains: BNF-like definitions, pattern specifications, format rules
- Processing: Often rendered with syntax highlighting or special formatting

**format**
- Purpose: Specify exact output templates and structure requirements
- Contains: Template patterns, output specifications, formatting rules
- Processing: Used as templates for generating structured output

**template**
- Purpose: Define reusable output patterns with placeholder substitution
- Contains: Handlebar-style templates, content patterns with variables
- Processing: Template engine processing with variable substitution

### Algorithm Fences

**alg**
- Purpose: Formal algorithm specifications and implementations
- Contains: Step-by-step procedures, algorithmic logic, computational processes
- Processing: May include execution simulation or step-through capabilities

**alg-pseudo**
- Purpose: Pseudocode representations of algorithms
- Contains: Language-agnostic algorithm descriptions, logical flow patterns
- Processing: Formatted for readability without language-specific syntax

### Special Fences

**artifact**
- Purpose: Generate structured output with metadata and special encoding
- Contains: SVG, code, documents with associated metadata and formatting
- Processing: Special artifact rendering with metadata preservation
- See: `./.claude/npl/fences/artifact.md` for complete specification

## Usage Patterns

### Basic Fence Usage
````xpl
```example
Here's how to use highlight syntax: `important term`
```
````

### Fence with Qualifiers
````xpl
```note|important
This syntax element should be used sparingly for maximum impact.
```
````

### Nested Content
````xpl
```format
Response structure:
```output
Status: <status>
Data: <data>
```
```
````

### Content Generation
````xpl
```example
[...3-5 lines|sample implementation showing the pattern]
```
````

## Processing Behavior

Fences provide semantic boundaries that:
- Guide content interpretation and rendering
- Enable specialized processing based on fence type
- Support nested structures and complex formatting
- Allow for enhanced display or interaction capabilities

## Quick Reference

| Fence Type | Primary Use | Content Focus |
|:---|:---|:---|
| `example` | Demonstration | Sample usage, illustrations |
| `syntax` | Definition | Grammar rules, patterns |
| `format` | Template | Output structure, formatting |
| `note` | Information | Clarifications, warnings |
| `diagram` | Visualization | Charts, flows, layouts |
| `artifact` | Generation | Special output with metadata |
| `template` | Reusability | Variable substitution patterns |
| `alg` | Algorithm | Formal procedures |
| `alg-pseudo` | Pseudocode | Language-agnostic algorithms |

## See Also
- `./.claude/npl/fences/example.md` - Example block patterns and formatting
- `./.claude/npl/fences/syntax.md` - Syntax definition block structure  
- `./.claude/npl/fences/format.md` - Format specification blocks
- `./.claude/npl/fences/note.md` - Note and comment block usage
- `./.claude/npl/fences/diagram.md` - Diagram representation techniques
- `./.claude/npl/fences/artifact.md` - Artifact output encoding and metadata
- `./.claude/npl/fences/template.md` - Template definition and usage patterns
- `./.claude/npl/fences/alg.md` - Algorithm specification blocks
- `./.claude/npl/fences/alg-pseudo.md` - Pseudocode algorithm conventions
- `./.claude/npl/formatting.md` - Overall formatting patterns and template systems