# Diagram Representation Blocks
Code fence for visual representations, flowcharts, and structural diagrams.

## Syntax
```diagram
[diagram content]
```

## Purpose
The `diagram` fence provides a way to include visual representations, system architectures, flowcharts, and other structural diagrams within prompts. These blocks help convey complex relationships, processes, and system designs that are difficult to express in text alone.

## Usage
Use diagram blocks when you need to:
- Show system architecture or component relationships
- Illustrate process flows and decision trees
- Visualize data structures or hierarchies
- Map out interaction patterns between agents
- Represent temporal sequences or state transitions

## Examples

### Basic Component Diagram
```diagram
[Component A] ---> [Component B]
[Component B] ---> [Component C]
```

### Process Flow Diagram
```diagram
[User Input] --> [Validation] --> [Processing] --> [Output Generation]
                      |
                      v
                 [Error Handling]
```

### Agent Interaction Diagram
```diagram
[User] --> @{search-agent} --> [Database]
             |
             v
        [Format Results] --> [User Display]
```

### System Architecture
```diagram
┌─────────────────┐
│   User Layer    │
├─────────────────┤
│  Agent Layer    │
├─────────────────┤
│ Processing Core │
├─────────────────┤
│  Data Storage   │
└─────────────────┘
```

### State Transition Diagram
```diagram
[Idle] --user_input--> [Processing]
[Processing] --success--> [Complete]
[Processing] --error--> [Error_State]
[Error_State] --retry--> [Processing]
[Complete] --reset--> [Idle]
```

### Hierarchical Structure
```diagram
NPL Framework
├── Core Syntax
│   ├── Placeholders
│   ├── Qualifiers
│   └── In-fill
├── Fences
│   ├── Example
│   ├── Syntax
│   └── Format
└── Special Sections
    ├── Agents
    └── Templates
```

## In NPL Source
From NPL@0.5 base.md, diagram blocks are described as special code sections that "outline the connection between different components visually" and help "the agent interpret the diagram for system insights."

The NPL framework recognizes diagrams as essential for conveying complex structural information that supplements textual instructions.

## Integration with NPL
Diagram blocks are valuable in:
- Agent definitions to show interaction patterns
- System documentation to illustrate architecture
- Process specifications to map workflows
- Template documentation to show data flow
- Instruction patterns to visualize logic flow

## Diagram Types and Conventions

### ASCII Art Diagrams
Simple text-based visual representations:
```diagram
Input --> [Filter] --> [Transform] --> Output
            |              |
            v              v
       [Log Error]    [Validate]
```

### Box and Arrow Diagrams
Component relationship mapping:
```diagram
┌──────────┐    ┌──────────┐    ┌──────────┐
│ Frontend │--->│ Backend  │--->│ Database │
└──────────┘    └──────────┘    └──────────┘
```

### Tree Structures
Hierarchical relationships:
```diagram
Root
├── Branch A
│   ├── Leaf 1
│   └── Leaf 2
└── Branch B
    └── Leaf 3
```

### Network Diagrams
Interconnected systems:
```diagram
[Node A] <---> [Node B]
    |            |
    v            v
[Node C] <---> [Node D]
```

### Mermaid Integration
NPL supports Mermaid syntax within diagram blocks for complex visualizations:
```diagram
flowchart TD
    A[User Request] --> B{Validation}
    B -->|Valid| C[Process]
    B -->|Invalid| D[Error Response]
    C --> E[Generate Output]
    E --> F[Return Result]
```

## Best Practices
- Keep diagrams simple and focused on key relationships
- Use consistent symbols and notation throughout
- Label connections and relationships clearly
- Consider using Mermaid syntax for complex diagrams
- Provide context or legend when using specialized notation
- Align diagram complexity with audience needs

## See Also
- `./.claude/npl/fences.md` - Overview of all fence types
- `./.claude/npl/instructing.md` - Instruction patterns including Mermaid
- `./.claude/npl/fences/example.md` - Example block formatting
- `./.claude/npl/special-section/agent.md` - Agent architecture patterns