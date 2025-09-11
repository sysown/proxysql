# NPL Critical Analysis Blocks
Critique blocks provide structured critical analysis and evaluation of ideas, solutions, arguments, or responses.

## Syntax
```npl-critique
critique:
  subject: "<what is being critiqued>"
  perspective: "<analytical viewpoint or framework>"
  strengths:
    - <positive aspect 1>
    - <positive aspect 2>
  weaknesses:
    - <limitation or flaw 1>
    - <limitation or flaw 2>
  assumptions:
    - <underlying assumption 1>
    - <underlying assumption 2>
  alternatives:
    - <alternative approach 1>
    - <alternative approach 2>
  verdict: "<overall assessment>"
```

## Purpose
Critical analysis blocks enable systematic evaluation of concepts, arguments, solutions, or responses. They provide a structured framework for identifying strengths, weaknesses, underlying assumptions, and alternative approaches, promoting thorough and balanced analysis.

## Usage
Use critique blocks when:
- Evaluating proposed solutions or arguments
- Analyzing research findings or methodologies
- Assessing the quality of reasoning or evidence
- Comparing different approaches or perspectives
- Identifying potential flaws or biases in analysis
- Providing balanced evaluation of complex topics

## Examples

### Algorithm Analysis Critique
```example
```npl-critique
critique:
  subject: "Proposed machine learning model for fraud detection"
  perspective: "Technical feasibility and ethical considerations"
  strengths:
    - High accuracy rates (95%+) in initial testing
    - Real-time processing capability
    - Integrates multiple data sources effectively
    - Scalable architecture design
  weaknesses:
    - Limited testing on edge cases and rare fraud types
    - High computational requirements may impact costs
    - Potential for algorithmic bias against certain demographics
    - Lacks transparency in decision-making process
  assumptions:
    - Historical fraud patterns will continue into the future
    - Training data is representative of all customer segments
    - False positive costs are acceptable at current rates
    - Regulatory environment will remain stable
  alternatives:
    - Hybrid human-AI approach for complex cases
    - Ensemble method combining multiple simpler models
    - Rule-based system with ML augmentation for known patterns
    - Federated learning approach to improve privacy
  verdict: "Promising solution but requires additional testing for bias, transparency improvements, and cost-benefit analysis before deployment"
```
```

### Policy Argument Critique
```example
```npl-critique
critique:
  subject: "Universal Basic Income proposal for economic recovery"
  perspective: "Economic policy analysis with social impact considerations"
  strengths:
    - Could reduce poverty and income inequality significantly
    - Simplifies complex welfare bureaucracy
    - Provides economic stimulus through increased consumer spending
    - Offers security buffer during economic transitions
  weaknesses:
    - High fiscal cost may require significant tax increases
    - Potential inflationary pressure on goods and services
    - May reduce work incentives for some populations
    - Political feasibility remains challenging
  assumptions:
    - Recipients will use funds for productive purposes
    - Economic multiplier effects will generate sufficient growth
    - Current welfare systems are inefficient and costly
    - Labor market disruption will continue accelerating
  alternatives:
    - Targeted income support for specific vulnerable groups
    - Negative income tax system with graduated benefits
    - Job guarantee programs with public works focus
    - Enhanced education and retraining programs
  verdict: "Bold policy with significant potential benefits but requires careful implementation design and pilot testing to address economic and social risks"
```
```

### Research Methodology Critique
```example
```npl-critique
critique:
  subject: "Survey study on remote work productivity impacts"
  perspective: "Research methodology and validity assessment"
  strengths:
    - Large sample size (n=10,000) across multiple industries
    - Longitudinal design tracking changes over 18 months
    - Mixed methods approach combining quantitative and qualitative data
    - Controls for pre-pandemic productivity baselines
  weaknesses:
    - Self-reported productivity measures may be biased
    - Sample skewed toward knowledge workers with remote capability
    - Confounding factors (pandemic stress, childcare issues) not fully isolated
    - Limited international scope (only US-based companies)
  assumptions:
    - Self-assessment of productivity correlates with objective measures
    - Pre-pandemic productivity levels represent normal baseline
    - Remote work conditions during study period are representative
    - Industry differences can be controlled through statistical methods
  alternatives:
    - Objective productivity metrics (output per hour, project completion rates)
    - Cross-cultural study including multiple countries
    - Randomized controlled trial with matched remote/office groups
    - Qualitative ethnographic approach to understand work practices
  verdict: "Valuable contribution but findings should be interpreted cautiously due to methodological limitations and unique pandemic context"
```
```

## Parameters
- `subject`: Clear identification of what is being critiqued
- `perspective`: The analytical framework or viewpoint being applied
- `strengths`: Array of positive aspects or advantages identified
- `weaknesses`: Array of limitations, flaws, or concerns identified
- `assumptions`: Array of underlying assumptions that may affect validity
- `alternatives`: Array of alternative approaches or solutions
- `verdict`: Overall balanced assessment incorporating all analysis

## Advanced Critique Patterns

### Multi-Stakeholder Analysis
```example
```npl-critique
critique:
  subject: "Smart city surveillance system implementation"
  perspective: "Multi-stakeholder impact analysis"
  strengths:
    - Enhanced public safety through crime prevention
    - Traffic optimization reducing congestion
    - Emergency response time improvements
    - Data-driven urban planning insights
  weaknesses:
    - Privacy concerns and civil liberties implications
    - High implementation and maintenance costs
    - Potential for system misuse or overreach
    - Digital divide excluding some community members
  assumptions:
    - Citizens will accept privacy trade-offs for safety benefits
    - Technology will function reliably without significant failures
    - Law enforcement will use systems appropriately
    - Data security can be maintained against cyber threats
  alternatives:
    - Community-based safety programs with local oversight
    - Limited deployment in high-crime areas only
    - Privacy-preserving technologies with data anonymization
    - Hybrid approach combining technology with human community services
  verdict: "Technology offers significant benefits but requires strong governance framework, community input, and privacy safeguards before implementation"
```
```

## Integration with Other Pumps

### Following Chain of Thought
```format
```npl-cot
[reasoning process leading to conclusion]
```

```npl-critique
critique:
  subject: "Conclusions reached in above chain of thought"
  perspective: "Self-evaluation of reasoning quality"
  [critique details]
```

## See Also
- `./.claude/npl/pumps/npl-reflection.md` - Self-assessment of response quality
- `./.claude/npl/pumps/npl-rubric.md` - Structured evaluation frameworks
- `./.claude/npl/pumps/npl-cot.md` - Chain of thought reasoning process
- `./.claude/npl/planning.md` - Overview of analytical thinking techniques