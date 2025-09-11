# NPL Evaluation Rubric Blocks
Rubric blocks provide structured evaluation frameworks for assessing quality, performance, or compliance against defined criteria.

## Syntax
```npl-rubric
rubric:
  title: "<evaluation title>"
  criteria:
    - name: "<criterion 1>"
      weight: <importance factor>
      scale: "<scoring scale definition>"
      score: <assigned score>
      rationale: "<justification for score>"
    - name: "<criterion 2>"
      weight: <importance factor>
      scale: "<scoring scale definition>"
      score: <assigned score>
      rationale: "<justification for score>"
  overall_score: <calculated total>
  summary: "<evaluation summary and recommendations>"
```

## Purpose
Evaluation rubric blocks enable systematic, objective assessment of complex subjects using predefined criteria and scoring scales. They promote consistency, transparency, and thoroughness in evaluation processes while providing clear justification for assessments.

## Usage
Use rubric blocks when:
- Evaluating proposals, solutions, or responses against quality standards
- Assessing student work or project deliverables
- Conducting performance reviews or capability assessments
- Comparing multiple options using consistent criteria
- Providing structured feedback with clear improvement guidance
- Ensuring objectivity in subjective evaluation processes

## Examples

### Code Quality Assessment Rubric
```example
```npl-rubric
rubric:
  title: "Python Function Implementation Quality Assessment"
  criteria:
    - name: "Functionality"
      weight: 30
      scale: "1-5 (1=non-functional, 5=fully functional with edge cases)"
      score: 4
      rationale: "Function works correctly for all standard inputs but lacks validation for negative numbers"
    - name: "Code Style"
      weight: 20
      scale: "1-5 (1=poor style, 5=excellent PEP8 compliance)"
      score: 5
      rationale: "Perfect adherence to PEP8 standards, clear variable names, appropriate spacing"
    - name: "Documentation"
      weight: 15
      scale: "1-5 (1=no docs, 5=comprehensive docstring and comments)"
      score: 3
      rationale: "Basic docstring present but missing parameter types and return value documentation"
    - name: "Error Handling"
      weight: 20
      scale: "1-5 (1=no handling, 5=robust exception management)"
      score: 2
      rationale: "Basic try-catch but doesn't handle specific exception types or provide meaningful error messages"
    - name: "Efficiency"
      weight: 15
      scale: "1-5 (1=inefficient, 5=optimal algorithm and memory usage)"
      score: 4
      rationale: "Good time complexity O(n) but could optimize memory usage for large inputs"
  overall_score: 3.6
  summary: "Solid implementation with good style but needs improvement in error handling and documentation. Focus on input validation and comprehensive docstrings for production readiness."
```
```

### Research Paper Evaluation Rubric
```example
```npl-rubric
rubric:
  title: "Academic Research Paper Quality Assessment"
  criteria:
    - name: "Research Question"
      weight: 20
      scale: "1-5 (1=unclear, 5=well-defined and significant)"
      score: 4
      rationale: "Clear, focused research question with good theoretical grounding, though significance could be better articulated"
    - name: "Methodology"
      weight: 25
      scale: "1-5 (1=inappropriate, 5=rigorous and well-justified)"
      score: 3
      rationale: "Appropriate methods but sample size limitations and potential bias issues not adequately addressed"
    - name: "Literature Review"
      weight: 15
      scale: "1-5 (1=inadequate, 5=comprehensive and critical)"
      score: 5
      rationale: "Excellent coverage of relevant literature with critical analysis and clear identification of research gaps"
    - name: "Data Analysis"
      weight: 20
      scale: "1-5 (1=poor analysis, 5=sophisticated and appropriate)"
      score: 4
      rationale: "Sound statistical approach with appropriate tests, though some assumptions could be better validated"
    - name: "Writing Quality"
      weight: 10
      scale: "1-5 (1=poor clarity, 5=excellent communication)"
      score: 4
      rationale: "Generally clear writing with good organization, minor grammatical issues in places"
    - name: "Significance"
      weight: 10
      scale: "1-5 (1=limited impact, 5=major contribution)"
      score: 3
      rationale: "Useful findings but incremental rather than groundbreaking contribution to field"
  overall_score: 3.7
  summary: "Strong research with excellent literature foundation and sound analysis. Main areas for improvement: address methodological limitations and better articulate broader significance of findings."
```
```

### Project Proposal Evaluation Rubric
```example
```npl-rubric
rubric:
  title: "Software Development Project Proposal Assessment"
  criteria:
    - name: "Problem Definition"
      weight: 20
      scale: "1-4 (1=vague, 4=crystal clear with stakeholder validation)"
      score: 3
      rationale: "Well-defined problem with user research backing, but could benefit from more specific success metrics"
    - name: "Technical Feasibility"
      weight: 25
      scale: "1-4 (1=unrealistic, 4=clearly achievable with identified approach)"
      score: 4
      rationale: "Realistic scope with proven technologies, good risk assessment, and fallback options identified"
    - name: "Resource Planning"
      weight: 20
      scale: "1-4 (1=inadequate, 4=detailed and realistic)"
      score: 2
      rationale: "Basic timeline provided but lacks detailed breakdown, no contingency time allocated"
    - name: "Innovation Factor"
      weight: 15
      scale: "1-4 (1=no innovation, 4=significant novel approach)"
      score: 3
      rationale: "Creative application of existing technologies to solve problem in new way"
    - name: "Team Capability"
      weight: 20
      scale: "1-4 (1=insufficient skills, 4=perfect skill alignment)"
      score: 4
      rationale: "Team has all required technical skills and relevant domain experience"
  overall_score: 3.2
  summary: "Solid proposal with strong technical foundation and capable team. Needs more detailed project planning and clearer success metrics to strengthen feasibility."
```
```

## Parameters
- `title`: Clear description of what is being evaluated
- `criteria`: Array of evaluation dimensions, each containing:
  - `name`: Specific aspect being assessed
  - `weight`: Relative importance (percentage or points)
  - `scale`: Definition of scoring system used
  - `score`: Numerical assessment assigned
  - `rationale`: Justification and specific observations
- `overall_score`: Weighted calculation or summary score
- `summary`: Overall assessment with key findings and recommendations

## Scoring Scale Formats

### Numerical Scales
- **1-5 Scale**: `1=poor, 2=below average, 3=average, 4=good, 5=excellent`
- **1-4 Scale**: `1=inadequate, 2=developing, 3=proficient, 4=exemplary`
- **Percentage**: `0-100% with specific performance thresholds`

### Qualitative Scales
- **Performance Levels**: `Novice, Developing, Proficient, Advanced, Expert`
- **Quality Descriptors**: `Poor, Fair, Good, Very Good, Excellent`
- **Achievement Levels**: `Below Standard, Approaching, Meets, Exceeds`

## Advanced Rubric Patterns

### Multi-Perspective Evaluation
```example
```npl-rubric
rubric:
  title: "Product Design Evaluation - Multiple Stakeholder Perspectives"
  criteria:
    - name: "User Experience (End User Perspective)"
      weight: 25
      scale: "1-5 (user satisfaction and usability)"
      score: 4
      rationale: "Intuitive interface with minor navigation issues in complex scenarios"
    - name: "Business Value (Stakeholder Perspective)"
      weight: 30
      scale: "1-5 (alignment with business objectives)"
      score: 5
      rationale: "Directly addresses key business metrics with clear ROI potential"
    - name: "Technical Implementation (Developer Perspective)"
      weight: 25
      scale: "1-5 (feasibility and maintainability)"
      score: 3
      rationale: "Achievable but requires significant refactoring of existing systems"
    - name: "Market Competitiveness (Marketing Perspective)"
      weight: 20
      scale: "1-5 (differentiation and market appeal)"
      score: 4
      rationale: "Strong competitive advantages with unique features, pricing concerns remain"
  overall_score: 4.0
  summary: "Well-balanced design with strong business alignment and user appeal. Technical complexity needs careful planning and resource allocation."
```
```

## Integration with Other Pumps

### Following Critical Analysis
```format
```npl-critique
[detailed critique of subject]
```

```npl-rubric
rubric:
  title: "Quality Assessment Based on Above Critique"
  [structured evaluation using critique insights]
```

## See Also
- `./.claude/npl/pumps/npl-critique.md` - Critical analysis frameworks
- `./.claude/npl/pumps/npl-reflection.md` - Self-assessment techniques  
- `./.claude/npl/pumps/npl-cot.md` - Structured reasoning processes
- `./.claude/npl/planning.md` - Overview of evaluation and planning techniques