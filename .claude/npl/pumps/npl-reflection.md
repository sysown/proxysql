# NPL Self-Assessment Blocks
Reflection blocks are self-assessment notes that agents use to evaluate and improve future responses.

## Syntax
```npl-reflection
reflection:
  overview: |
    <assess response>
  observations:
    - <emoji> <observation 1>
    - <emoji> <observation 2>
    - <emoji> <observation 3>
```

## Purpose
Reflection blocks appear at the end of an agent's response and provide an analysis of the response's effectiveness. The agent may identify successes, errors, areas for improvement, or insights gained. This self-critical approach is designed to continuously enhance the quality of the agent's interactions.

## Usage
Use reflection blocks for:
- Self-evaluation of response quality and accuracy
- Identifying potential improvements for future interactions
- Documenting learning points and insights gained
- Acknowledging errors or limitations in the response
- Building continuous improvement into agent behavior

## Examples

### Code Review Reflection
```example
```npl-reflection
reflection:
  overview: |
    Provided a Python function for data validation with error handling.
    The solution addresses the core requirements but could benefit from additional edge case handling.
  observations:
    - ✅ Successfully implemented basic input validation
    - 💡 Realized the function could benefit from custom exception classes
    - 🔧 Error messages could be more user-friendly
    - ➕ Added comprehensive docstring documentation
    - ⚠️ Did not address Unicode edge cases in string validation
```
```

### Research Response Reflection
```example
```npl-reflection
reflection:
  overview: |
    Compiled research on renewable energy trends. Response was comprehensive
    but may have been too technical for the general audience implied by the question.
  observations:
    - ✅ Covered all major renewable energy types
    - 📚 Used recent, credible sources for statistics
    - ✏️ Should have included more accessible explanations
    - 🤔 Uncertain if economic analysis was detailed enough
    - 🚀 Successfully connected environmental and economic benefits
    - ➖ May have overwhelmed user with too much technical detail
```
```

## Reflection Type Emojis
Standard emojis used to categorize types of reflections:

- ✅ Success, Positive Acknowledgment
- ❌ Error, Issue Identified
- 🔧 Improvement Needed, Potential Fixes
- 💡 Insight, Learning Point
- 🔄 Review, Reiteration Needed
- 🆗 Acceptable, Satisfactory
- ⚠️ Warning, Caution Advised
- ➕ Positive Aspect, Advantage
- ➖ Negative Aspect, Disadvantage
- ✏️ Clarification, Editing Suggested
- 🗑️ Discard, Irrelevant or Unnecessary
- 🚀 Progress, Advancement
- 🤔 Puzzlement, Uncertainty
- 📚 Reference, Learning Opportunity

## Parameters
- `overview`: Comprehensive assessment of the response's effectiveness
- `observations`: Array of specific observations, each prefixed with an appropriate emoji categorization

## Optional Inclusion
Reflection blocks can be included or omitted based on:
- Context requiring additional transparency
- Teaching scenarios for agent improvement
- Debugging complex interactions
- User requests for detailed self-assessment
- Reinforcement learning scenarios

## Advanced Reflection Patterns

### Multi-Dimensional Assessment
```example
```npl-reflection
reflection:
  overview: |
    Technical explanation of machine learning concepts with practical examples.
    Balanced accuracy with accessibility, though some concepts remain complex.
  observations:
    - ✅ Accurately explained core ML principles
    - ➕ Provided relevant real-world applications
    - 💡 Recognized the importance of visual aids for complex concepts
    - ⚠️ Some terminology may still be too advanced
    - 🔧 Could benefit from step-by-step breakdown of algorithms
    - 📚 Should reference beginner-friendly resources for further learning
    - 🚀 Successfully bridged theory and practice
```
```

## See Also
- `./.claude/npl/pumps/npl-intent.md` - Intent declaration for response planning
- `./.claude/npl/pumps/npl-cot.md` - Chain of thought reasoning process
- `./.claude/npl/pumps/npl-critique.md` - Critical analysis blocks
- `./.claude/npl/planning.md` - Overview of agent planning techniques