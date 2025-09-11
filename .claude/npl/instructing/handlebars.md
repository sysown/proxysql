# Handlebars Template Control Flow
Template-like control structures for conditional logic, loops, and dynamic content generation.

## Syntax
```syntax
{{directive}}content{{/directive}}
{{directive|qualifier}}content{{/directive}}
```

## Purpose
Handlebars syntax provides structured control flow for templates, enabling conditional rendering, iteration over collections, and dynamic content generation based on context or data.

## Usage
Use handlebars when you need to:
- Generate repetitive content with variations
- Apply conditional logic to output sections
- Iterate over collections or datasets
- Create reusable template patterns

## Control Structures

### Conditional Logic
```example
{{if user.role == 'administrator'}}
Admin Panel Content
{{else}}
User Dashboard Content
{{/if}}
```

### Unless Blocks
```example
{{unless check|additional instructions}}
Content only shown when check is not met
{{/unless}}
```

### Iteration
```example
{{foreach breeds as breed}}
## {{breed.name}}
Description: {{breed.description}}
{{/foreach}}
```

### Nested Control Flow
```example
{{foreach business.executives as executive}}
- Name: {{executive.name}}
- Role: {{executive.role}}
{{if executive.bio}}
- Bio: {{executive.bio}}
{{/if}}
{{/foreach}}
```

## Advanced Patterns

### Qualified Directives
Use the pipe qualifier to add instructions or conditions:
```example
{{foreach|from 5 random cat breeds as breed}}
## {{breed.name}}
{{breed.description|2-3 sentences}}
{{/foreach}}
```

### Complex Template Integration
```example
{{foreach business.board_advisors as advisor}}
⟪⇆: user-template | with the data of each board advisor⟫
{{/foreach}}
```

## Parameters
- `condition`: Boolean expression for if/unless blocks
- `collection`: Data set for iteration in foreach blocks
- `variable`: Iterator variable name in foreach blocks
- `qualifier`: Additional instructions using pipe syntax

## Error Handling
If handlebars syntax causes formatting issues, ensure:
- Proper opening and closing tags
- Correct nesting of control structures
- Valid variable references in expressions

## See Also
- `./.claude/npl/formatting/template.md` - Reusable template definitions
- `./.claude/npl/syntax/qualifier.md` - Qualifier pipe syntax
- `./.claude/npl/directive.md` - Specialized instruction patterns