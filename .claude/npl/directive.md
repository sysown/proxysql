# NPL Directives
Specialized instruction patterns for precise agent behavior modification and output control using structured command syntax.

## Syntax
`⟪emoji: instruction⟫` - Primary directive pattern with emoji prefix and instruction content

## Purpose
Directives provide fine-grained control over agent behavior, output formatting, and interaction patterns through structured command syntax that extends beyond basic prompt instructions.

## Usage
Use directives when you need:
- Specialized output formatting (tables, templates)
- Time-based or conditional execution
- Interactive element choreography
- Unique identifier management
- Explanatory annotations
- Section reference marking
- Explicit instruction emphasis

## Core Directive Types

### Table Formatting
**Syntax**: `⟪📅: (column alignments and labels) | content description⟫`

Controls structured table output with specified column alignments, headers, and content descriptions.

### Temporal Control
**Syntax**: `⟪⏳: Time Condition or Instruction⟫`

Commands the agent to consider timing and duration for task execution, including scheduled actions and time-based constraints.

### Template Integration
**Syntax**: `⟪⇐: template-name | application context⟫`

Integrates predefined templates into outputs with specified application contexts and data binding.

### Interactive Elements
**Syntax**: `⟪🚀: Action or Behavior Definition⟫`

Choreographs interactive elements and agent reactivity based on user interactions and system events.

### Identifier Management
**Syntax**: `⟪🆔: Entity or Context Requiring ID⟫`

Generates and manages unique identifiers for various entities, sessions, and data records.

### Explanatory Notes
**Syntax**: `⟪📖: Detailed Explanation⟫`

Appends instructive comments to elucidate expectations behind prompts and provide context for behaviors.

### Section References
**Syntax**: `⟪📂: {identifier}⟫`

Marks sections with unique identifiers for easy reference, updates, and cross-referencing.

### Explicit Instructions
**Syntax**: `⟪➤: instruction | elaboration⟫`

Provides direct and precise instructions to the agent for maximum clarity and specificity.

## Examples

```example
Table with custom formatting:
⟪📅: (#:left, prime:right, english:center label Numbers) | first 5 prime numbers⟫
```

```example
Scheduled task execution:
⟪⏳: At the end of each day⟫ Generate summary report of user activities
```

```example
Template integration:
⟪⇐: user-card | with executive data⟫
```

```example
Interactive behavior:
⟪🚀: User clicks submit button⟫ Validate form and show confirmation
```

## Parameters
- `emoji`: Visual indicator specifying the directive type and behavior
- `instruction`: The primary command or specification
- `elaboration`: Optional additional context or parameters (separated by `|`)

## Behavior Control
Directives operate at a higher precedence than basic syntax elements and can override default agent behaviors. They provide structured ways to:

- Format complex output structures
- Define conditional and temporal logic
- Integrate reusable components
- Manage system state and identifiers
- Add contextual information

## See Also
- `.claude/npl/directive/📅.md` - Table formatting directive details
- `.claude/npl/directive/⏳.md` - Temporal control directive details
- `.claude/npl/directive/🚀.md` - Interactive element directive details
- `.claude/npl/directive/➤.md` - Explicit instruction directive details
- `.claude/npl/syntax.md` - Basic syntax elements
- `.claude/npl/prefix.md` - Response mode indicators
