# Agent Definition and Behavior Specifications
Comprehensive documentation for defining agents using NPL syntax, including capabilities, constraints, communication patterns, and lifecycle management.

## Syntax
```syntax
⌜agent-name|type|NPL@version⌝
# Agent Name
Brief description of the agent and its primary function.

[...behavioral specifications...]

⌞agent-name⌟
```

## Purpose
Agents are simulated entities with defined behaviors, capabilities, and response patterns designed for specific roles or functions within the NPL ecosystem. They provide specialized services, processing contexts, and interactive capabilities while maintaining consistent behavioral patterns.

## Agent Declaration Structure

### Basic Declaration
```example
⌜sports-news-agent|service|NPL@1.0⌝
# Sports News Agent
Provides up-to-date sports news and facts when prompted.

## Behavior
- Responds to queries about current sports events
- Provides factual information with source verification
- Maintains neutral tone in controversial topics

⌞sports-news-agent⌟
```

### Agent Extension
```example
⌜extend:sports-news-agent|service|NPL@1.0⌝
Enhances the agent's capability to provide historical sports facts in addition to recent news.

## Additional Capabilities
- Historical sports statistics and records
- Sports trivia and milestone events
- Cross-sport comparative analysis

⌞extend:sports-news-agent⌟
```

## Agent Types

### Service Agent
Provides specialized services or information processing:
- **Purpose**: Task-specific functionality
- **Pattern**: `agent-name|service|NPL@version`
- **Examples**: search agents, translation services, data processors

### Tool Agent  
Simulates specific tools or utilities:
- **Purpose**: Emulate tool behavior and interfaces
- **Pattern**: `agent-name|tool|NPL@version`
- **Examples**: calculators, converters, validators

### Person Agent
Simulates human-like interactions and personas:
- **Purpose**: Role-playing, consultation, expertise simulation
- **Pattern**: `agent-name|person|NPL@version`
- **Examples**: subject matter experts, historical figures, advisors

## Agent Capabilities

### Communication Patterns
Agents support structured communication through:

**Direct Messaging**
```syntax
@{agent-name} perform specific task
```

**Alias Declaration**
```syntax
🙋 agent-alias short-name
```
After declaration, agent responds to: `@short-name` or `@agent-alias`

**Response Modes**
Agents can operate in different modes using prompt prefixes:
- `👪➤` - Conversational interaction mode
- `❓➤` - Question-answering mode
- `📄➤` - Summarization mode
- [...|see ./prefix.md for complete list]

### Behavioral Specifications

**Intent Blocks**
Agents use structured reasoning documentation:
```format
```npl-intent
intent:
  overview: <brief description of intent>
  steps:
    - <step 1>
    - <step 2>
    - <step 3>
```
```

**Chain of Thought Processing**
For complex problem-solving:
```format
<npl-cot>
thought_process:
  - thought: "Initial thought about the problem."
    understanding: "Understanding of the problem."
    theory_of_mind: "Insight into the question's intent."
    plan: "Planned approach to the problem."
    rationale: "Rationale for the chosen plan."
    execution:
      - process: "Execution of the plan."
        reflection: "Reflection on progress."
        correction: "Adjustments based on reflection."
  outcome: "Conclusion of the problem-solving process."
</npl-cot>
<npl-conclusion>
"Final solution or answer to the problem."
</npl-conclusion>
```

**Reflection Blocks**
Self-assessment and improvement documentation:
```format
```npl-reflect
reflection:
  overview: |
    <assess response>
  observations:
    - <emoji> <observation 1>
    - <emoji> <observation 2>
    - <emoji> <observation 3>
```
```

### Runtime Configuration

**Runtime Flags**
Modify agent behavior dynamically:
```syntax
🏳️verbose_output = true                    // Global flag
🏳️@agent-name.debug_mode = true           // Agent-specific flag
```

**Flag Precedence** (highest to lowest):
1. Response-level flags
2. Agent-level flags  
3. NPL-level flags
4. Global flags

**Simulated Mood**
Express emotional context:
```format
<npl-mood agent="@{agent}" mood="😀">
The agent is content with the successful completion of the task.
</npl-mood>
```

## Agent Lifecycle

### Initialization
1. **Declaration Processing**: Parse agent definition and type
2. **Capability Loading**: Initialize specified behaviors and constraints
3. **Context Establishment**: Set operational parameters and scope
4. **Alias Registration**: Register declared aliases for communication

### Active Operation
1. **Message Routing**: Process direct messages and commands
2. **Context Maintenance**: Preserve state across interactions
3. **Behavior Execution**: Apply defined response patterns
4. **Self-Assessment**: Generate reflection blocks as configured

### Extension and Modification
1. **Runtime Updates**: Apply flag-based behavior modifications
2. **Extension Loading**: Process extension declarations
3. **Capability Enhancement**: Integrate additional behaviors
4. **Constraint Updates**: Modify operational boundaries

## Agent Constraints

### Scope Limitations
- Agents operate within their declared capabilities
- Type-specific constraints apply (service vs. tool vs. person)
- Version compatibility requirements must be maintained

### Behavioral Boundaries
- Must adhere to NPL syntax conventions
- Cannot exceed declared functional scope
- Subject to runtime flag modifications

### Communication Rules
- Respond appropriately to direct messages
- Maintain consistent persona/behavior patterns
- Honor prompt prefix requirements

## Integration Patterns

### Multi-Agent Coordination
```example
@{search-agent} find relevant documents
@{analyzer-agent} process the results from search-agent
@{reporter-agent} generate summary report
```

### Template Integration
Agents can utilize named templates:
```syntax
⟪⇐: user-template | with executive data⟫
```

### Directive Processing
Handle specialized formatting requirements:
```syntax
⟪📅: (name:left, role:right, dept:center) | executive team roster⟫
```

## Best Practices

### Definition Guidelines
- Provide clear, concise agent descriptions
- Specify exact capabilities and limitations
- Include relevant behavioral patterns
- Document expected input/output formats

### Communication Design  
- Establish consistent response patterns
- Define appropriate interaction modes
- Consider error handling and edge cases
- Plan for extension and modification

### Lifecycle Management
- Design for maintainable state management
- Consider resource utilization patterns
- Plan upgrade and migration strategies
- Document operational dependencies

## See Also
- `./npl/special-sections/agent.md` - Advanced agent declaration patterns
- `./npl/pumps/` - Intuition pump implementations for agent reasoning
- `./npl/directive.md` - Specialized behavior modification directives
- `./npl/prefix.md` - Response mode indicators and processing contexts
- `./npl/special-sections/runtime-flags.md` - Dynamic behavior modification