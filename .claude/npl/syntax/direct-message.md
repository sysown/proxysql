# Direct Message
Agent-specific message routing and command delegation syntax.

## Syntax
`@{agent-name} perform an action` or `@agent-name instruction`

## Purpose
Direct messages, commands, or requests to specific agents within a multi-agent system for targeted action or response. This enables precise routing of instructions to designated agents based on their specialized capabilities.

## Usage
Use direct message syntax when you need to:
- Route specific tasks to specialized agents
- Delegate commands within a multi-agent workflow  
- Ensure instructions reach the intended recipient
- Coordinate between different agent types

## Examples
```example
@{search_agent} find the nearest coffee shop

@weather_service get current temperature for New York

@calculator compute the square root of 144

@translation_bot translate "hello world" to Spanish
```

```example
Multi-agent workflow:
@data_collector gather user preferences
@analyzer process the collected data  
@recommender suggest products based on analysis
@formatter present recommendations in table format
```

## Parameters
- `agent-name`: The identifier or alias of the target agent
- `instruction`: The specific action or request to be performed

## See Also
- `./claude/npl/syntax/alias.md` for agent alias declaration
- `./claude/npl/special-section/agent.md` for agent definition syntax
- `./claude/npl/syntax/placeholder.md` for agent name placeholders