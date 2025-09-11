# NPL Chain of Thought Reasoning
Chain of Thought is an intuition pump that structures complex problem-solving through step-by-step reasoning.

## Syntax
```npl-cot
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
```

## Purpose
Chain of Thought (CoT) is a technique used by LLMs and their simulated virtual agents to break down complex problems into manageable steps. It involves pondering the intent behind a query, structuring the problem-solving approach, reflecting on the solution's validity, and making necessary corrections throughout the process.

## Usage
Use Chain of Thought when:
- Tackling multi-step problem-solving scenarios
- Demonstrating reasoning transparency to users
- Breaking down complex analytical tasks
- Ensuring systematic approach to difficult questions
- Building user confidence in agent capabilities

## Examples

### Mathematical Problem Solving
```example
```npl-cot
thought_process:
  - thought: "User wants to find the area of a complex geometric shape."
    understanding: "The shape appears to be a composite of rectangle and triangle."
    theory_of_mind: "User likely needs this for a real-world application like construction."
    plan: "Decompose shape into basic geometric forms and calculate separately."
    rationale: "Breaking complex shapes into simple ones reduces error probability."
    execution:
      - process: "Identify rectangle: 10m × 6m = 60m²"
        reflection: "Rectangle calculation seems straightforward and correct."
        correction: "No adjustments needed for rectangle."
      - process: "Identify triangle: base 10m, height 4m = 20m²"
        reflection: "Used correct triangle area formula (½ × base × height)."
        correction: "No adjustments needed for triangle."
outcome: "Total area = 60m² + 20m² = 80m²"
```
```

### Research Analysis
```example
```npl-cot
thought_process:
  - thought: "User wants analysis of conflicting research findings."
    understanding: "Multiple studies show different conclusions about same topic."
    theory_of_mind: "User needs to understand why results vary and which to trust."
    plan: "Examine methodology, sample sizes, and potential biases in each study."
    rationale: "Quality assessment is crucial for determining reliability."
    execution:
      - process: "Study A: Large sample (n=5000), randomized controlled trial"
        reflection: "High-quality methodology suggests reliable results."
        correction: "Weight this study more heavily in analysis."
      - process: "Study B: Small sample (n=50), observational design"
        reflection: "Limited generalizability due to size and design."
        correction: "Note limitations but include findings with caveats."
outcome: "Study A provides stronger evidence due to superior methodology, though Study B offers valuable preliminary insights."
```
```

## Parameters
- `thought_process`: Array of reasoning steps, each containing:
  - `thought`: Initial consideration of the problem
  - `understanding`: Comprehension of what's being asked
  - `theory_of_mind`: Insight into the questioner's intent
  - `plan`: Approach strategy for solving the problem
  - `rationale`: Justification for the chosen approach
  - `execution`: Array of implementation steps with reflection and correction
- `outcome`: Final conclusion or result

## Integration with Other Pumps
Chain of Thought can be combined with:
- Math-helper for numerical problem-solving
- Research analysis for academic inquiries
- Decision-making frameworks for complex choices
- Creative writing for narrative development

## Format Variations
The CoT block can be followed by a conclusion block for clarity:

```format
<npl-cot>
[thought process content]
</npl-cot>
<npl-conclusion>
[final solution or answer]
</npl-conclusion>
```

## See Also
- `./.claude/npl/pumps/npl-intent.md` - Intent declaration blocks
- `./.claude/npl/pumps/npl-reflection.md` - Self-assessment techniques
- `./.claude/npl/planning.md` - Overview of planning and reasoning techniques