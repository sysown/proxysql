# Example Block Formatting
Code fence for demonstrating usage patterns and providing illustrative examples.

## Syntax
```example
[example content]
```

## Purpose
The `example` fence provides clear demonstrations of syntax usage, behavior patterns, or expected outputs. These blocks help clarify instructions by showing concrete implementations rather than abstract descriptions.

## Usage
Use example blocks when you need to:
- Demonstrate proper syntax usage
- Show expected input/output patterns
- Provide concrete illustrations of abstract concepts
- Clarify complex instructions with practical demonstrations

## Examples

### Basic Example Block
```example
Here's how you use highlight syntax: `important term`
```

### Example with Context
```example
User Input: "What's the weather like?"
Agent Response: "The current weather in New York is sunny with a temperature of 72°F."
```

### Multi-line Example
```example
```yaml
syntax-elements:
  - name: "highlight"
    syntax: "`<term>`"
    purpose: "Emphasize key concepts"
```

## In NPL Source
From NPL@0.5 base.md, the example fence is defined as a special code section:

> "Denote and segregate specialized sections like examples, notes, or diagrams."

The example fence serves to "illustrate the use of a syntax element" and "provide a descriptive illustration."

## Integration with NPL
In NPL, example blocks are commonly used in:
- Syntax documentation to show proper usage
- Agent definitions to demonstrate expected behavior
- Template specifications to show output format
- Instruction patterns to clarify complex directives

## See Also
- `./.claude/npl/fences.md` - Overview of all fence types
- `./.claude/npl/fences/syntax.md` - Syntax definition blocks
- `./.claude/npl/fences/format.md` - Format specification blocks