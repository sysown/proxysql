# Planning & Reasoning Patterns
Advanced thinking techniques and structured reasoning approaches for complex problem-solving and agent behavior orchestration.

## Overview
Planning in NPL encompasses structured reasoning techniques, thinking patterns, and cognitive frameworks that guide agents through complex problem-solving processes. These patterns provide systematic approaches to breaking down problems, analyzing solutions, and constructing well-reasoned responses.

## Core Planning Components

### Intent Blocks
`npl-intent` - Structured transparency into agent decision-making processes

Intent blocks provide clear documentation of the reasoning steps an agent takes when constructing responses, offering users insight into the agent's thought process.

```syntax
<npl-intent>
intent:
  overview: <brief description of intent>
  steps:
    - <step 1>
    - <step 2>
    - <step 3>
</npl-intent>
```

**Purpose**: Enhance transparency and trust by exposing the logical flow behind responses.

**Usage**: Include at the beginning of complex responses or when debugging mode is active.

### Chain of Thought
`npl-cot` - Structured problem decomposition and systematic reasoning

Chain of Thought breaks complex problems into manageable steps, providing a systematic approach to problem-solving with explicit reflection and correction mechanisms.

```syntax
<npl-cot>
thought_process:
  - thought: "Initial assessment of the problem"
    understanding: "What the problem involves"
    theory_of_mind: "Intent behind the question"
    plan: "Approach to solving it"
    rationale: "Why this approach"
    execution:
      - process: "Implementation steps"
        reflection: "Assessment of progress"
        correction: "Adjustments made"
  outcome: "Final conclusion"
</npl-cot>
<npl-conclusion>
Final solution or answer to the problem.
</npl-conclusion>
```

**Purpose**: Enable systematic breakdown of complex reasoning tasks with built-in self-correction.

**Usage**: Apply to multi-step problems requiring structured analysis and verification.

### Reflection Blocks
`npl-reflection` - Self-assessment and continuous improvement mechanisms

Reflection blocks enable agents to evaluate their own responses, identify areas for improvement, and document learning insights.

```syntax
<npl-reflection>
reflection:
  overview: |
    <assessment of response quality and effectiveness>
  observations:
    - <emoji> <specific observation 1>
    - <emoji> <specific observation 2>
    - <emoji> <specific observation 3>
</npl-reflection>
```

**Reflection Type Indicators**:
- ✅ Success, positive acknowledgment
- ❌ Error, issue identified
- 🔧 Improvement needed, potential fixes
- 💡 Insight, learning point
- 🔄 Review, reiteration needed
- 🆗 Acceptable, satisfactory
- ⚠️ Warning, caution advised
- ➕ Positive aspect, advantage
- ➖ Negative aspect, disadvantage
- ✏️ Clarification, editing suggested

**Purpose**: Foster continuous learning and response quality improvement.

**Usage**: Include at the end of responses for self-evaluation and learning documentation.

## Advanced Planning Patterns

### Critique Systems
`npl-critique` - Systematic evaluation and quality assessment frameworks

Critique systems provide structured approaches to evaluating solutions, identifying weaknesses, and suggesting improvements.

### Rubric-Based Assessment
`npl-rubric` - Standardized evaluation criteria and scoring frameworks

Rubric systems enable consistent evaluation of responses against predefined criteria and quality standards.

### Panel Discussions
`npl-panel` - Multi-perspective analysis and collaborative reasoning

Panel patterns simulate multiple viewpoints or expert perspectives on complex issues, providing comprehensive analysis.

### Tangential Exploration
`npl-tangent` - Structured exploration of related concepts and implications

Tangent patterns allow for controlled exploration of related ideas while maintaining focus on the primary objective.

## Integration Patterns

### Planning with Agent Behaviors
Planning patterns can be integrated with agent definitions to create consistent reasoning approaches across different agent types:

```example
⌜analyst-agent|service|NPL@1.0⌝
# Data Analyst Agent
Provides structured analysis with built-in reasoning transparency.

## Default Response Pattern
All responses should include:
1. <npl-intent> block outlining analysis approach
2. <npl-cot> for complex data interpretation
3. <npl-reflection> for quality assessment

⌞analyst-agent⌟
```

### Conditional Planning Application
Planning patterns can be applied conditionally based on:
- Query complexity level
- User request for transparency
- Debugging or development mode
- Agent learning phases

### Layered Reasoning Approaches
Multiple planning patterns can be combined for comprehensive analysis:

1. **Intent** → Document planned approach
2. **Chain of Thought** → Execute structured reasoning
3. **Critique** → Evaluate solution quality
4. **Reflection** → Learn for future improvements

## Planning Pattern Configuration

### Runtime Flags for Planning
```syntax
⌜🏳️
🏳️planning.intent_blocks = conditional
🏳️planning.reflection_mode = learning
🏳️planning.cot_verbosity = detailed
⌟
```

### Agent-Specific Planning Settings
```syntax
🏳️@research_agent.planning.reflection_required = true
🏳️@simple_agent.planning.intent_minimal = true
```

## Complex Reasoning Structures

### Multi-Stage Problem Solving
For problems requiring multiple phases of analysis:

1. **Problem Decomposition** - Break into manageable components
2. **Solution Space Exploration** - Identify possible approaches
3. **Option Evaluation** - Assess trade-offs and constraints
4. **Implementation Planning** - Structure execution steps
5. **Outcome Validation** - Verify solution effectiveness

### Collaborative Reasoning
When multiple perspectives or expertise areas are needed:

```example
<npl-panel>
perspectives:
  - role: "Technical Expert"
    viewpoint: "Implementation feasibility and constraints"
  - role: "User Experience Designer"
    viewpoint: "Usability and user impact"
  - role: "Business Analyst"
    viewpoint: "Cost-benefit and strategic alignment"
consensus: "Integrated recommendation considering all viewpoints"
</npl-panel>
```

## Quality Assurance in Planning

### Reasoning Validation
- **Logical Consistency** - Ensure steps follow logically
- **Completeness Check** - Verify all aspects are addressed
- **Assumption Validation** - Identify and verify assumptions
- **Alternative Consideration** - Explore other possible approaches

### Error Detection and Correction
Planning patterns include mechanisms for:
- Identifying reasoning gaps
- Correcting logical errors
- Updating conclusions based on new information
- Learning from mistakes for future improvement

## See Also
- `./npl/pumps/` - Individual intuition pump specifications
- `./npl/special-sections/agent.md` - Agent behavior integration
- `./npl/special-sections/runtime-flags.md` - Planning configuration options
- `./npl/fences/` - Fence syntax for planning blocks