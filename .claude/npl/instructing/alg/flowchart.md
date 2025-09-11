# Flowchart Representations
Visual algorithm specification using flowchart diagrams and Mermaid syntax for algorithm flow representation.

## Syntax
`alg-flowchart` fence type or `mermaid flowchart` for visual algorithm representations

## Purpose
Represent algorithm logic flow using standardized flowchart symbols and visual connections to illustrate decision points, processes, and data flow in algorithmic sequences.

## Usage
Use flowchart representations when visual clarity of algorithm flow is important, for complex decision trees, or when communicating algorithms to stakeholders who prefer visual documentation.

## Examples

### Basic Decision Flow
```alg-flowchart
mermaid
flowchart TD
    A[Start] --> B[Get User Input]
    B --> C{Input Valid?}
    C -->|Yes| D[Process Input]
    C -->|No| E[Show Error Message]
    D --> F[Display Result]
    E --> B
    F --> G[End]
```

### Loop Structure
```alg-flowchart
mermaid
flowchart TD
    A[Start] --> B[Initialize counter = 0]
    B --> C[Initialize sum = 0]
    C --> D{counter < array.length?}
    D -->|Yes| E[Add array[counter] to sum]
    E --> F[Increment counter]
    F --> D
    D -->|No| G[Return sum]
    G --> H[End]
```

### Complex Algorithm with Multiple Paths
```alg-flowchart
mermaid
flowchart TD
    A[Start: User Login] --> B[Get Credentials]
    B --> C{Valid Format?}
    C -->|No| D[Show Format Error]
    D --> B
    C -->|Yes| E[Check Database]
    E --> F{User Exists?}
    F -->|No| G[Show User Not Found]
    G --> B
    F -->|Yes| H{Password Correct?}
    H -->|No| I[Increment Failed Attempts]
    I --> J{Attempts < 3?}
    J -->|Yes| K[Show Password Error]
    K --> B
    J -->|No| L[Lock Account]
    L --> M[Show Account Locked]
    M --> N[End]
    H -->|Yes| O[Generate Session Token]
    O --> P[Redirect to Dashboard]
    P --> N
```

### Nested Decision Structure
```alg-flowchart
mermaid
flowchart TD
    A[Start] --> B[Read User Role]
    B --> C{Role = Admin?}
    C -->|Yes| D[Load Admin Panel]
    C -->|No| E{Role = Manager?}
    E -->|Yes| F[Load Manager Dashboard]
    E -->|No| G{Role = User?}
    G -->|Yes| H[Load User Interface]
    G -->|No| I[Load Guest View]
    D --> J[End]
    F --> J
    H --> J
    I --> J
```

## Standard Flowchart Symbols

### Process Symbols
- **Rectangle**: Process or action step
- **Diamond**: Decision point (yes/no, true/false)
- **Oval**: Start/End terminals
- **Circle**: Connector or junction point
- **Parallelogram**: Input/Output operations

### Flow Connections
- **Solid Arrow**: Normal flow direction
- **Dashed Arrow**: Alternative or exception flow
- **Labeled Arrows**: Condition indicators (Yes/No, True/False)

## Mermaid Flowchart Syntax

### Basic Elements
```syntax
flowchart TD
    A[Process Box]
    B{Decision Diamond}
    C((Circle Node))
    D[/Input Output/]
    E[[Subroutine]]
    F[(Database)]
```

### Connection Types
```syntax
A --> B    // Solid arrow
A -.-> B   // Dotted arrow
A ==> B    // Thick arrow
A -- text --> B  // Arrow with text
A -->|label| B   // Arrow with label
```

### Styling Options
```syntax
classDef processClass fill:#e1f5fe
classDef decisionClass fill:#fff3e0
classDef errorClass fill:#ffebee

class A,D processClass
class B decisionClass
class E errorClass
```

## Parameters
- **Direction**: `TD` (top-down), `LR` (left-right), `BT` (bottom-top), `RL` (right-left)
- **Node Shapes**: Rectangle `[]`, Diamond `{}`, Circle `()`, Parallelogram `/\`
- **Connection Labels**: Text descriptions for flow conditions

## See Also
- `./pseudo.md` for text-based algorithm specifications
- `./python.md` for Python implementation patterns
- `./javascript.md` for JavaScript implementation patterns
- `../../fences/mermaid.md` for complete Mermaid diagram syntax