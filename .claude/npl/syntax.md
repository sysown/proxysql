# NPL Syntax Overview
Core syntax elements and conventions for the Noizu Prompt Lingua framework.

## Purpose
This document provides a comprehensive overview of NPL's syntax elements, conventions, and patterns. It serves as the central reference point for all syntax-related documentation and guides users to detailed specifications for complex elements.

## Syntax Categories

### Core Syntax Elements

**highlight**
: `` `term` `` - Emphasize key concepts and important terms for clarity
```example
In object-oriented programming, an `object` represents an instance of a class.
```

**attention**
: `🎯 important instruction` - Mark critical instructions requiring special focus
```example  
🎯 Remember to validate all user inputs before processing.
```

**placeholder**
: `<term>`, `{term}`, `<<qualifier>:term>` - Indicate expected input or output locations
```example
Hello {user.name}, your order status is <order.status>.
```

**in-fill**
: `[...]`, `[...|details]`, `[...size]` - Mark areas for dynamic content generation
```example
The event will feature several keynote speakers including [...].
```

**qualifier**
: `term|instructions` - Extend syntax with additional details or conditions
```example
{payment_methods|common for usa and india}
```

**attention-alias**
: `🙋 alias` - Declare alternative names for agents or services
```example
🙋 spreadsheet-helper sph
```

### Validation and Examples

**validation**
: `✔ positive example` or `❌ negative example` - Provide clear behavioral demonstrations
```example
✔ The function returns a valid response for all tested inputs.
❌ The function throws unhandled exceptions for edge cases.
```

**separator**
: `﹍` - Create clear visual separations between examples or sections
```example
Module 1: Basics of programming
﹍
Module 2: Advanced topics
```

### Content Generation

**inference**
: `...`, `etc.` - Indicate additional similar items should be generated
```example
The grocery list should include dairy products like milk, yogurt, ...
```

**literal-output**
: `` `{~l|exact text}` `` - Ensure specified text is output exactly as provided
```example
When quoting Shakespeare, use `{~l|To be, or not to be}` exactly.
```

**omission**
: `[___]` - Content intentionally left out for brevity
```example
The full specification includes [...], [___], and error handling.
```

### Communication and Routing

**direct-message**
: `@{agent} instruction` - Route messages to specific agents for action
```example
@{search_agent} find the nearest coffee shop.
```

**value-placeholder**
: `⟪content⟫`, `{...}`, `<...>` - Direct agent to inject specific content
```example
Hello ⟪user.formatted_name⟫, welcome back!
```

### Logic and Operations

**logic-operators**
: Mathematical and conditional expressions for reasoning
```example
if (user.role == 'administrator') { Show admin panel } else { Show user dashboard }
∑(sold_items) - Calculate total items sold
(sports_enthusiasts ∩ health_focused) - Find common customers
```

## Special Code Sections

**fence-blocks**
: Specialized sections with type indicators for different content types
```syntax
```example
[...example content...]
```

```note  
[...explanatory notes...]
```

```diagram
[Component A] ---> [Component B]
```
```

Common fence types: `example`, `note`, `diagram`, `syntax`, `format`, `template`, `artifact`

## Size Indicators

Size qualifiers can be used with in-fill and placeholder syntax:

- `p`: paragraphs
- `pg`: pages  
- `l`: lines
- `s`: sentences
- `w`: words
- `i`: items
- `r`: rows
- `t`: tokens

Examples: `[...3-5w]` (3-5 words), `[...2p]` (2 paragraphs), `[...3-9+r]` (3 to 9 or more rows)

## Quick Reference

| Pattern | Purpose | Example |
|---------|---------|---------|
| `` `term` `` | Highlight | `` `object` `` |
| `🎯 instruction` | Attention | `🎯 Validate inputs` |
| `<term>` | Placeholder | `<user.name>` |
| `[...]` | In-fill | `[...3s]` |
| `term\|qualify` | Qualifier | `{options\|usa only}` |
| `✔/❌ example` | Validation | `✔ Good result` |
| `@{agent}` | Direct message | `@{helper} task` |
| `...` | Inference | `items: a, b, ...` |

## Navigation Guide

### Detailed Syntax Documentation
- `./syntax/highlight.md` - Backtick emphasis syntax
- `./syntax/placeholder.md` - Input/output placeholder conventions
- `./syntax/in-fill.md` - Content generation markers
- `./syntax/qualifier.md` - Pipe qualifier syntax
- `./syntax/attention.md` - Critical instruction markers
- `./syntax/logic-operators.md` - Mathematical and conditional logic

### Size and Formatting
- `./syntax/in-fill-size.md` - Complete size indicator reference
- `./syntax/separate-examples.md` - Example separation conventions
- `./syntax/literal-output.md` - Exact text reproduction

### Communication Patterns  
- `./syntax/direct-message.md` - Agent-specific routing
- `./syntax/alias.md` - Agent alias declarations
- `./syntax/value-placeholder.md` - Dynamic content injection

### Deep-Dive References
- `./syntax/deep-dive/placeholder.md` - Advanced placeholder patterns
- `./syntax/deep-dive/logic-operators.md` - Complete logic operator reference
- `./syntax/deep-dive/in-fill-size.md` - Comprehensive size indicators

## See Also
- `.claude/npl/fences.md` - Code fence types and usage
- `.claude/npl/directive.md` - Specialized instruction patterns  
- `.claude/npl/prefix.md` - Response mode indicators
- `.claude/npl/formatting.md` - Output formatting and templates
