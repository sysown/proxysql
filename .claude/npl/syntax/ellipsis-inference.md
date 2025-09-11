# Ellipsis Inference
Continuation and inference patterns that signal agents to generate or consider similar/additional items based on established context and patterns.

## Syntax
`...` (ellipsis)  
`etc.` (et cetera)  
`..` (short ellipsis)  
`.` (minimal continuation)

## Purpose
Ellipsis inference enables agents to understand when a list, sequence, or pattern is incomplete and should be extended with contextually appropriate additional items. This allows for efficient prompt construction without exhaustively listing all possible entries while maintaining semantic coherence.

## Usage
Use ellipsis inference when you need to:
- Indicate that a list is not exhaustive and should include additional items
- Signal pattern continuation based on established examples
- Generate contextually appropriate content following a pattern
- Avoid repetitive enumeration while ensuring comprehensive coverage

## Examples

### Basic List Extension
```example
The grocery list should include dairy products like milk, yogurt, ...
```
The agent infers additional dairy products such as cheese, butter, cream, etc.

### Category Completion
```example
Popular programming languages include Python, JavaScript, Java, ...
```
Agent adds languages like C++, C#, TypeScript, Go, Rust, etc.

### Pattern Recognition
```example
Sequential numbers: 2, 4, 6, 8, ...
```
Agent continues the even number pattern: 10, 12, 14, 16, etc.

### Contextual Animal Examples
```example
Animals in the zoo: birds, cats, ... 
```
Based on context, agent might add: dogs, horses, zebras, elephants, lions, tigers, etc.

### Academic Subjects
```example
STEM fields include Science, Technology, Engineering, etc.
```
Agent completes with Mathematics and related disciplines.

### File Extensions
```example
Image formats: .jpg, .png, .gif, ...
```
Agent adds .bmp, .tiff, .svg, .webp, etc.

## Inference Patterns

### Categorical Inference
When items belong to a clear category, agents infer related items:
```example
Citrus fruits: oranges, lemons, ...
→ limes, grapefruits, tangerines
```

### Sequential Inference  
When items follow a pattern or sequence:
```example
Days of the week: Monday, Tuesday, ...
→ Wednesday, Thursday, Friday, Saturday, Sunday
```

### Hierarchical Inference
When items represent different levels or types:
```example
Text editors: Notepad, VS Code, ...
→ Sublime Text, Atom, Vim, Emacs
```

## Usage Variations
- `...` - Standard continuation indicator
- `etc.` - Formal "and so forth" indicator  
- `..` - Abbreviated continuation
- `.` - Minimal pattern continuation

## Best Practices
- Provide sufficient context for meaningful inference
- Use consistent item types to guide inference direction
- Consider domain-specific patterns when establishing examples
- Ensure examples are representative of the desired category

## See Also
- `./fill-in.md` - Content generation area markers
- `./qualifier.md` - Qualifier syntax for inference guidance  
- `./../../formatting/template.md` - Template-based pattern generation