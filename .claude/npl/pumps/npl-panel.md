# NPL Panel Discussion Format
Panel discussion format simulates multi-perspective analysis and collaborative reasoning through structured dialogue.

## Syntax
```npl-panel
participants:
  - name: <participant_name>
    role: <expertise_area>
    perspective: <viewpoint_description>
discussion:
  - speaker: <participant_name>
    point: <main_argument_or_observation>
    reasoning: <supporting_logic>
  - speaker: <participant_name>
    response: <reaction_or_counterpoint>
    evidence: <supporting_data>
consensus:
  areas_of_agreement: [<agreed_points>]
  remaining_questions: [<unresolved_issues>]
  recommended_action: <suggested_next_steps>
```

## Purpose
Panel discussions provide multi-dimensional analysis of complex topics by simulating diverse expert perspectives. This format enables comprehensive exploration of issues through structured dialogue, helping to identify blind spots, surface different viewpoints, and build toward more robust conclusions.

## Usage
Use panel discussions when:
- Analyzing complex problems requiring multiple expertise areas
- Evaluating controversial or nuanced topics
- Building consensus through structured debate
- Exploring different stakeholder perspectives
- Making decisions that benefit from diverse input
- Teaching critical thinking through perspective-taking

## Examples

### Technology Ethics Panel
```example
```npl-panel
participants:
  - name: Dr. Sarah Chen
    role: AI Ethics Researcher
    perspective: Focus on algorithmic bias and fairness
  - name: Marcus Rodriguez
    role: Software Engineer
    perspective: Practical implementation challenges
  - name: Prof. Aisha Patel
    role: Legal Scholar
    perspective: Regulatory and compliance frameworks
discussion:
  - speaker: Dr. Sarah Chen
    point: "Current AI systems perpetuate existing biases in hiring decisions"
    reasoning: "Training data reflects historical discrimination patterns"
  - speaker: Marcus Rodriguez
    response: "While true, bias detection tools are improving rapidly"
    evidence: "New fairness metrics can identify disparate impact during development"
  - speaker: Prof. Aisha Patel
    point: "Legal frameworks lag behind technological capabilities"
    reasoning: "Current employment law doesn't address algorithmic decision-making"
  - speaker: Dr. Sarah Chen
    response: "That's exactly why proactive ethics review is crucial"
    evidence: "Companies implementing ethics boards see 40% fewer bias incidents"
consensus:
  areas_of_agreement: 
    - Bias in AI hiring tools is a documented problem
    - Technical solutions are advancing but insufficient alone
    - Legal clarity is needed for compliance
  remaining_questions:
    - What specific metrics should be mandatory?
    - How to balance efficiency with fairness?
    - Who bears liability for algorithmic decisions?
  recommended_action: "Develop industry standards combining technical, ethical, and legal requirements"
```
```

### Business Strategy Panel
```example
```npl-panel
participants:
  - name: James Mitchell
    role: CFO
    perspective: Financial sustainability and risk management
  - name: Lisa Park
    role: Head of Marketing
    perspective: Customer acquisition and brand positioning
  - name: David Kumar
    role: Operations Manager
    perspective: Scalability and resource allocation
discussion:
  - speaker: Lisa Park
    point: "Expanding to European markets could double our customer base"
    reasoning: "Market research shows 60% brand recognition in target demographics"
  - speaker: James Mitchell
    response: "The regulatory costs alone could exceed $2M in year one"
    evidence: "GDPR compliance, tax structures, and legal entity setup"
  - speaker: David Kumar
    point: "Our current infrastructure can't support 24/7 European operations"
    reasoning: "Customer service and order fulfillment require local presence"
  - speaker: Lisa Park
    response: "Partnership model could reduce infrastructure investment"
    evidence: "Similar companies achieved 70% cost reduction through local partners"
consensus:
  areas_of_agreement:
    - European market presents significant opportunity
    - Direct expansion carries substantial upfront costs
    - Infrastructure challenges are real but solvable
  remaining_questions:
    - Which countries to prioritize for initial entry?
    - Partnership vs. direct investment trade-offs?
    - Timeline for break-even on expansion costs?
  recommended_action: "Conduct detailed feasibility study for partnership model in Germany and UK"
```
```

## Parameters
- `participants`: Array of panel members with defined roles and perspectives
  - `name`: Identifier for the participant
  - `role`: Area of expertise or professional background
  - `perspective`: Specific viewpoint or focus area they bring
- `discussion`: Structured dialogue between participants
  - `speaker`: Which participant is contributing
  - `point`: Main argument, observation, or position
  - `reasoning`: Logic or rationale supporting the point
  - `response`: Reaction to another participant's contribution
  - `evidence`: Supporting data, research, or examples
- `consensus`: Summary of dialogue outcomes
  - `areas_of_agreement`: Points where participants align
  - `remaining_questions`: Unresolved issues requiring further exploration
  - `recommended_action`: Suggested next steps or decisions

## Variations
Panel discussions can be adapted for different contexts:
- **Academic panels**: Focus on research findings and theoretical frameworks
- **Business panels**: Emphasize practical implementation and ROI considerations
- **Policy panels**: Address regulatory, ethical, and social implications
- **Technical panels**: Deep-dive into implementation details and trade-offs

## Facilitation Patterns
Effective panel discussions often follow these patterns:
1. **Opening positions**: Each participant states their initial viewpoint
2. **Cross-examination**: Participants question and challenge each other
3. **Evidence presentation**: Supporting data and examples are shared
4. **Synthesis**: Common ground and differences are identified
5. **Forward-looking**: Recommendations and next steps are developed

## See Also
- `./.claude/npl/pumps/npl-panel-inline-feedback.md` - Inline feedback panels
- `./.claude/npl/pumps/npl-panel-group-chat.md` - Group discussion panels
- `./.claude/npl/pumps/npl-panel-reviewer-feedback.md` - Reviewer feedback panels
- `./.claude/npl/pumps/npl-critique.md` - Critical analysis blocks
- `./.claude/npl/planning.md` - Overview of planning and reasoning techniques