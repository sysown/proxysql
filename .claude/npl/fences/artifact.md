# Artifact Fence
NPL-artifacts structure output and request artifact output with special encoding and metadata syntax.

## Syntax
```artifact
<artifact content with metadata>
```

## Purpose
NPL-artifacts provide a structured way to encode output that requires special handling, metadata attachment, or specific rendering contexts. They support various content types including SVG, code, and other specialized formats.

## Usage
Use artifact fences when output needs to be:
- Rendered with specific encoding or metadata
- Processed as a standalone deliverable
- Associated with type-specific handling instructions
- Packaged with additional context or parameters

## Examples

### SVG Artifact
```example
```artifact
type: svg
title: "Simple Circle"
<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="40" fill="blue" />
</svg>
```
```

### Code Artifact
```example
```artifact
type: code
language: python
title: "Fibonacci Function"
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
```
```

### Document Artifact
```example
```artifact
type: document
format: markdown
title: "Project README"
# My Project
This is a sample project with documentation.
## Features
- Feature 1
- Feature 2
```
```

## Parameters
- `type`: Content type (svg, code, document, etc.)
- `language`: Programming language for code artifacts
- `title`: Display title for the artifact
- `format`: Document format specification
- `encoding`: Special encoding requirements
- `metadata`: Additional context information

## See Also
- `./../../formatting.md` - Output formatting patterns overview
- `./template.md` - Template definition blocks
- `./../special-section/named-template.md` - Named template definitions