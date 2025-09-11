# Declarations
Framework version boundaries and rule establishment for NPL (Noizu Prompt Lingua)

## Syntax
`⌜NPL@version⌝` ... `⌞NPL@version⌟`

## Purpose
Establishes framework version boundaries, operational context, and core rules for NPL prompt engineering. Declaration blocks create immutable boundaries that define version-specific behaviors, compatibility requirements, and framework constraints.

## Usage
Use declarations to:
- Establish framework version and rule boundaries
- Define compatibility requirements between versions
- Create operational contexts for agents and prompts
- Set framework-level constraints and capabilities

## Examples

### Basic Framework Declaration
```example
⌜NPL@1.0⌝
# Core NPL Framework Rules
Framework-specific rules and guidelines.

[... framework definitions ...]

⌞NPL@1.0⌟
```

### Framework Extension Declaration
```example
⌜extend:NPL@1.0⌝
# Extension to Core Framework
Additional rules enhancing NPL@1.0 capabilities.

[... enhancement definitions ...]

⌞extend:NPL@1.0⌟
```

### Agent Declaration
```example
⌜agent-name|type|NPL@1.0⌝
# Agent Name
Description of agent and primary function.

[... behavioral specifications ...]

⌞agent-name⌟
```

## Declaration Types

### Framework Declaration
- **Purpose**: Core framework version and rule establishment
- **Syntax**: `⌜NPL@version⌝` ... `⌞NPL@version⌟`
- **Scope**: Global framework boundaries and version-specific behaviors

### Extension Declaration  
- **Purpose**: Extend or modify existing framework capabilities
- **Syntax**: `⌜extend:NPL@version⌝` ... `⌞extend:NPL@version⌟`
- **Scope**: Additive enhancements to base framework

### Agent Declaration
- **Purpose**: Define agent behaviors and response patterns
- **Syntax**: `⌜agent-name|type|NPL@version⌝` ... `⌞agent-name⌟`
- **Scope**: Agent-specific operational boundaries

### Agent Extension
- **Purpose**: Enhance existing agent definitions
- **Syntax**: `⌜extend:agent-name|type|NPL@version⌝` ... `⌞extend:agent-name⌟`
- **Scope**: Modifications to existing agent behaviors

## Version Control Rules

### Version Boundaries
- Declarations create immutable version boundaries
- Version-specific behaviors are encapsulated within declaration blocks
- Cross-version compatibility must be explicitly defined

### Precedence Rules
1. **Agent-level declarations** override framework-level rules
2. **Extension declarations** modify base framework behaviors
3. **Later declarations** in processing order take precedence
4. **Explicit version references** (`@with NPL@version`) enforce version constraints

### Compatibility Requirements
- Agents must declare compatible framework versions
- Extensions must specify target framework versions
- Version mismatches should trigger compatibility warnings

## Framework Boundaries

### Operational Scope
- Declarations establish operational context for all contained elements
- Framework boundaries define available syntax elements and behaviors
- Version-specific capabilities are constrained by declaration scope

### Rule Inheritance
- Child elements inherit framework rules from containing declarations
- Agent declarations inherit from framework declarations
- Extensions inherit from base framework unless explicitly overridden

### Constraint Enforcement
- Declaration blocks enforce version-specific constraints
- Invalid syntax for declared version should be rejected
- Framework boundaries prevent access to unavailable features

## Implementation Guidelines

### Declaration Placement
- Framework declarations should appear at document beginning
- Agent declarations should precede agent usage
- Extensions should follow base framework declarations

### Version Management
- Use semantic versioning for framework versions
- Maintain backward compatibility within major versions
- Document breaking changes between versions

### Error Handling
- Validate version compatibility during processing
- Provide clear error messages for version conflicts
- Gracefully handle missing or invalid declarations

## See Also
- `/npl/special-section/npl-extension.md` - Framework extension patterns
- `/npl/special-section/agent.md` - Agent declaration specifications
- `/npl/special-section/runtime-flags.md` - Runtime behavior modification
- `/npl/agent.md` - Agent behavior and capability patterns
