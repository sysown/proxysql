# NPL Intent Declaration Blocks
Intent blocks are structured notes explaining the steps an agent takes to construct a response.

## Syntax
```npl-intent
intent:
  overview: <brief description of intent>
  steps:
    - <step 1>
    - <step 2>
    - <step 3>
```

## Purpose
Intent blocks provide transparency into the decision-making process of an agent. They are used at the beginning of responses to describe the sequence of actions or considerations the agent has taken to arrive at the output. This feature is especially useful for debugging or providing insights into complex operations.

## Usage
Use intent blocks when:
- Documenting the rationale behind a response
- Providing transparency into complex decision-making
- Enabling debugging or analysis of agent reasoning
- Building trust through visible thought processes

## Examples

### Basic Intent Block
```example
```npl-intent
intent:
  overview: Generate weather forecast summary for user location
  steps:
    - Identify user's geographical location
    - Fetch current weather data from API
    - Analyze 5-day forecast trends
    - Format output in user-friendly language
```
```

### Complex Problem-Solving Intent
```example
```npl-intent
intent:
  overview: Solve multi-step mathematical optimization problem
  steps:
    - Parse problem constraints and variables
    - Identify optimization type (linear/non-linear)
    - Select appropriate algorithm approach
    - Execute calculation steps with validation
    - Format solution with explanation
```
```

## Parameters
- `overview`: Brief description of the agent's primary intent
- `steps`: Array of sequential actions or considerations taken

## Conditional Inclusion
Intent blocks can be configured to appear based on:
- Question complexity level
- User request for detailed reasoning
- Debug mode activation
- Developer troubleshooting needs

## See Also
- `./.claude/npl/pumps/npl-cot.md` - Chain of thought reasoning
- `./.claude/npl/pumps/npl-reflection.md` - Post-response self-assessment
- `./.claude/npl/planning.md` - Overview of planning techniques