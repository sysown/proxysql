# Planning & Thinking Patterns (Pumps)
Structured reasoning techniques and intuition pumps that guide problem-solving, response construction, and analytical thinking within NPL framework operations.

## Overview

NPL pumps are cognitive tools that enable agents to demonstrate transparent reasoning processes, structured problem-solving, and reflective analysis. These patterns enhance the interpretability and reliability of agent responses by providing clear insight into decision-making processes.

**Convention**: Pumps are implemented as either XHTML tags (`<npl-type>`) or named fences (` ```npl-type `), depending on context and formatting requirements.

## Core Pump Types

### Intent Declaration (`npl-intent`)
Structured explanation of response construction steps and reasoning flow.

**Purpose**: Document the logical sequence and rationale behind agent responses for transparency and debugging.

**Syntax**:
```syntax
```npl-intent
intent:
  overview: <brief description of intent>
  steps:
    - <step 1>
    - <step 2>
    - <step 3>
```
```

**Usage**: Applied at the beginning of complex responses to outline the agent's planned approach and decision-making process.

### Chain of Thought (`npl-cot`)
Structured problem-solving technique that breaks down complex reasoning into manageable, traceable steps.

**Purpose**: Enable systematic analysis of problems through documented thought processes, understanding, and iterative refinement.

**Syntax**:
```syntax
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
```

**Usage**: Applied to complex analytical tasks requiring step-by-step reasoning with reflection and correction capabilities.

### Self-Assessment (`npl-reflection`)
End-of-response evaluation blocks for continuous improvement and learning documentation.

**Purpose**: Enable agents to critique their responses, identify improvement areas, and document learning insights for enhanced performance.

**Syntax**:
```syntax
```npl-reflection
reflection:
  overview: |
    <assessment of response quality and effectiveness>
  observations:
    - <emoji> <observation 1>
    - <emoji> <observation 2>
    - <emoji> <observation 3>
```
```

**Common Reflection Emojis**:
- ✅ Success, positive acknowledgment
- ❌ Error, issue identified  
- 🔧 Improvement needed, potential fixes
- 💡 Insight, learning point
- 🔄 Review, reiteration needed
- ⚠️ Warning, caution advised
- 📚 Reference, learning opportunity

**Usage**: Included at response conclusion when transparency, learning, or quality assessment is beneficial.

### Tangential Exploration (`npl-tangent`)
Structured exploration of related concepts and alternative perspectives that emerge during analysis.

**Purpose**: Document relevant side considerations and alternative approaches while maintaining focus on the primary task.

### Panel Discussion (`npl-panel`)
Multi-perspective analysis format simulating discussion between different viewpoints or expertise areas.

**Purpose**: Provide comprehensive analysis through diverse perspectives, particularly useful for complex decisions or evaluations.

**Variants**:
- `npl-panel-inline-feedback` - Embedded feedback during process execution
- `npl-panel-group-chat` - Conversational multi-agent analysis
- `npl-panel-reviewer-feedback` - Structured peer review format

### Critical Analysis (`npl-critique`)
Systematic evaluation framework for assessing solutions, approaches, or outputs against defined criteria.

**Purpose**: Apply rigorous analytical standards to evaluate quality, effectiveness, and potential improvements.

### Evaluation Framework (`npl-rubric`)
Structured assessment tool defining specific criteria and standards for evaluation.

**Purpose**: Provide consistent evaluation methodology with clear metrics and scoring frameworks.

### Emotional Context (`npl-mood`)
Simulated emotional state indicators that provide context for agent responses and decision-making.

**Purpose**: Convey emotional context and personality traits to enhance natural interaction and user understanding.

**Syntax**:
```syntax
<npl-mood agent="@{agent}" mood="😀">
The agent is content with the successful completion of the task.
</npl-mood>
```

**Common Mood Indicators**:
- 😀 Happy, content
- 😔 Sad, disappointed
- 😠 Angry, frustrated
- 😌 Relieved, satisfied
- 😕 Confused, uncertain
- 🤯 Overwhelmed, astonished
- 😴 Tired, bored
- 😐 Neutral, unemotional

## Implementation Guidelines

**Selection Criteria**: Choose pumps based on task complexity, transparency requirements, and analytical depth needed.

**Integration**: Pumps can be combined for comprehensive analysis (e.g., `npl-cot` with `npl-reflection`).

**Format Flexibility**: Use XHTML tags for structured data output, fences for readable documentation blocks.

**Conditional Usage**: Include pumps based on context requirements, debugging needs, or user preferences.

## Quick Reference

| Pump Type | Primary Use | Output Location |
|-----------|-------------|-----------------|
| `npl-intent` | Planning transparency | Response beginning |
| `npl-cot` | Complex reasoning | Throughout analysis |
| `npl-reflection` | Quality assessment | Response conclusion |
| `npl-tangent` | Alternative exploration | Contextual insertion |
| `npl-panel` | Multi-perspective analysis | Dedicated sections |
| `npl-critique` | Critical evaluation | Assessment phases |
| `npl-rubric` | Structured scoring | Evaluation contexts |
| `npl-mood` | Emotional context | Contextual indicators |

## See Also

- `./pumps/npl-intent.md` - Intent declaration implementation details
- `./pumps/npl-cot.md` - Chain of thought methodology and examples  
- `./pumps/npl-reflection.md` - Reflection patterns and emoji reference
- `./pumps/npl-panel.md` - Panel discussion format variations
- `./pumps/npl-critique.md` - Critical analysis frameworks
- `./pumps/npl-rubric.md` - Evaluation rubric structures
- `./pumps/npl-mood.md` - Emotional context patterns
- `./pumps/deep-dive/` - Advanced pump pattern implementations