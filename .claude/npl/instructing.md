⌜npl-doc-gen|instructing|NPL@1.0⌝
# NPL Instructing Patterns
Comprehensive overview of instruction patterns and control structures for directing complex agent behaviors and response construction.

## Purpose
Instructing patterns provide specialized syntax for controlling agent behavior through structured commands, templates, and logical constructs. These patterns enable precise direction of complex reasoning processes, iterative refinement, and systematic problem-solving approaches.

## Core Instructing Methods

### Handlebars
Template-like control structures for dynamic content generation and conditional logic.

**Syntax**: `{{if}}`, `{{foreach}}`, `{{with}}` style constructs

**Usage**: Dynamic content rendering, conditional output, data iteration

**Example**:
```handlebars
{{if user.role == 'administrator'}}
  Show admin panel
{{else}}
  Show user dashboard
{{/if}}

{{foreach business.executives as executive}}
- Name: {{executive.name}}
- Role: {{executive.role}}
{{/foreach}}
```

### Alg-Speak
Algorithm specification language for precise computational instruction.

**Syntax**: `alg`, `alg-pseudo`, `alg-*` fences for algorithm specification

**Usage**: Step-by-step algorithm definition, pseudocode representation, computational logic

**Example**:
```alg-pseudo
algorithm: find_maximum
input: array of numbers
output: maximum value

1. initialize max = first element
2. for each remaining element:
   - if element > max, set max = element
3. return max
```

### Annotation
Iterative refinement patterns for code changes, UX modifications, and design interactions.

**Syntax**: Annotation markers and refinement indicators

**Usage**: Progressive improvement, feedback integration, design iteration

**Purpose**: Enable systematic refinement of complex outputs through structured feedback loops

### Second-Order Logic
Higher-order reasoning patterns for meta-level instruction and control.

**Syntax**: Logical quantifiers, predicate logic, recursive definitions

**Usage**: Complex reasoning tasks, formal specification, meta-programming concepts

**Reference**: Load `./npl/instructing/second-order.md` for detailed patterns

### Symbolic Logic
Mathematical and logical representations for precise reasoning control.

**Syntax**: Mathematical operators, set theory, logical connectives

**Examples**:
- Conditional logic: `if (condition) { action } else { alternative }`
- Set operations: `A ∪ B`, `A ∩ B` 
- Summation: `∑(data_set)`
- Intersection for segmentation: `(sports_enthusiasts ∩ health_focused)`

### Formal Proof
Structured proof techniques for rigorous logical reasoning.

**Syntax**: Proof steps, logical inference, theorem construction

**Usage**: Mathematical reasoning, logical verification, systematic argumentation

**Reference**: Load `./npl/instructing/formal-proof.md` for proof structures

## Control Flow Patterns

### Conditional Rendering
Use logical operators to control content generation based on conditions.

```example
if (user.authenticated) {
  Display personalized content
} else {
  Show login prompt
}
```

### Iteration Control
Template systems for repeating patterns over data sets.

```example
{foreach items as item}
  Process item: {item.name}
  Status: {item.status}
{/foreach}
```

### Data Qualification
Extend syntax with conditional and contextual details.

```example
{payment_methods|common for usa and india}
{speakers|relevant to AI conference}
```

## Advanced Instructing Features

### Mermaid Diagrams
Flowchart-based instruction specification for complex workflows.

**Types**: `flowchart`, `stateDiagram`, `sequenceDiagram`

**Usage**: Visual instruction flow, state management, process orchestration

### Template Integration
Seamlessly embed predefined templates into dynamic outputs.

**Syntax**: `⟪⇐: template-name⟫` for template application

**Purpose**: Consistent formatting across varied content types

### Interactive Element Choreography  
Define responsive behaviors and user interaction patterns.

**Syntax**: `⟪🚀: Action or Behavior Definition⟫`

**Usage**: Dynamic UI responses, conditional interactions, time-based behaviors

## Pattern Complexity Levels

### Basic Instructions
- Simple conditional logic
- Direct template application
- Linear algorithm steps

### Intermediate Control
- Nested conditionals
- Complex iteration patterns
- Multi-step reasoning chains

### Advanced Orchestration
- Meta-level instruction patterns
- Recursive template structures
- Formal logical specifications

## Integration Guidelines

### When to Use Instructing Patterns
- Complex multi-step processes requiring structured control
- Dynamic content generation with conditional logic
- Systematic problem-solving and reasoning tasks
- Template-based output with variable content
- Interactive or responsive agent behaviors

### Pattern Selection
- **Handlebars**: Dynamic content and conditional rendering
- **Alg-speak**: Computational and algorithmic tasks  
- **Annotation**: Iterative improvement processes
- **Symbolic logic**: Mathematical and logical reasoning
- **Formal proof**: Rigorous logical verification

### Error Handling
If instructing patterns produce unexpected results:
1. Verify syntax correctness against pattern specifications
2. Check for proper nesting and closure of control structures
3. Validate data context and variable availability
4. Load detailed pattern documentation for troubleshooting

## Quick Reference

**Template Control**: `{{if condition}} ... {{else}} ... {{/if}}`

**Algorithm Specification**: Use `alg-*` fences with step-by-step instructions

**Logic Operators**: `∑`, `∪`, `∩`, conditional statements

**Template Integration**: `⟪⇐: template-name | context⟫`

**Interactive Behavior**: `⟪🚀: trigger conditions⟫`

## See Also
- `./npl/instructing/handlebars.md` - Complete template syntax reference
- `./npl/instructing/alg-speak.md` - Algorithm specification language details
- `./npl/instructing/annotation.md` - Iterative refinement patterns  
- `./npl/instructing/second-order.md` - Higher-order logic constructs
- `./npl/instructing/symbolic-logic.md` - Mathematical reasoning patterns
- `./npl/instructing/formal-proof.md` - Proof structure specifications
- `./npl/syntax/logic-operators.md` - Mathematical and conditional operators
- `./npl/directive.md` - Specialized directive patterns for behavior control
⌞npl-doc-gen⌟