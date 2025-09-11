# Agent Alias Declaration
Allows agents to be referred to by alternative names for easier invocation and communication.

## Syntax
`🙋 <alias> [additional-aliases...]`

## Purpose
The alias syntax enables users to establish shorter, more convenient names for agents, improving workflow efficiency and communication. This is particularly useful when working with agents that have lengthy or complex names, or when creating contextual shortcuts for frequently accessed agents.

## Usage
Use agent aliases when you need to:
- Create shorter references to agents with long names
- Establish contextual names that are easier to remember
- Enable quick agent invocation in conversation flows
- Set up multiple naming conventions for the same agent

## Examples

### Basic Agent Alias
```example
🙋 spreadsheet-helper sph
```
After this declaration, users can invoke the agent using either the full name or the alias:
- `@spreadsheet-helper` (original name)
- `@sph` (alias)

### Multiple Aliases
```example  
🙋 data-analysis-agent daa analyst stats-helper
```
This creates multiple aliases for the same agent, allowing flexible invocation patterns.

### Service Agent Alias
```example
🙋 customer-support-bot support cs-bot help
```
Creates intuitive aliases for a customer support agent that users can easily remember and type.

## Parameters
- `alias`: The primary alternative name for the agent (required)
- `additional-aliases`: Optional additional alternative names (space-separated)

## Behavior Notes
- Aliases must be unique within the current context
- Original agent name remains valid after alias declaration  
- Aliases are case-sensitive by default
- Multiple aliases can be declared for a single agent

## See Also
- `./agent.md` - Complete agent definition syntax
- `./direct-message.md` - Agent-specific message routing using aliases
- `./../../special-section/agent.md` - Agent declaration blocks