# Named Template Definitions
Named template definitions for creating reusable output patterns and structured content generation.

## Syntax
`⌜🧱 template-name⌝[...template definition...]⌞🧱 template-name⌟`

## Purpose
Named templates define reusable output formats and patterns that can be consistently applied across different contexts. They enable modular content generation, standardized formatting, and efficient template management within the NPL framework.

## Usage
Use named templates when you need to:
- Create consistent output formats across multiple agents
- Define reusable content structures for common use cases
- Standardize data presentation patterns
- Enable template-based content generation
- Maintain formatting consistency across responses

## Template Structure
Named templates typically include:
- **Template name**: Unique identifier for the template
- **Input parameters**: Variables and data sources
- **Output format**: Structure and formatting specifications
- **Processing instructions**: Logic and conditional rendering

## Examples

```example
⌜🧱 user-card
@with NPL@1.0

## Input Parameters
- user.name: Full name of the user
- user.role: User's role or title  
- user.bio: Brief biographical information
- user.avatar: Profile image URL (optional)

```template
<div class="user-card">
  {{if user.avatar}}<img src="{user.avatar}" alt="{user.name}" class="avatar">{{/if}}
  <h3>{user.name}</h3>
  <p class="role">{user.role}</p>
  <p class="bio">{user.bio}</p>
</div>
```
⌞🧱 user-card⌟
```

```example
⌜🧱 analysis-report
@with NPL@1.0

## Input Parameters
- report.title: Report title
- report.summary: Executive summary
- report.data: Analysis data points
- report.conclusions: Key findings

```template
# {report.title}

## Executive Summary
{report.summary}

## Data Analysis
{{foreach report.data as datapoint}}
- **{datapoint.metric}**: {datapoint.value} ({datapoint.trend})
{{/foreach}}

## Key Findings
{{foreach report.conclusions as finding}}
{finding.rank}. {finding.description}
   - **Impact**: {finding.impact}
   - **Confidence**: {finding.confidence}%
{{/foreach}}

---
*Report generated on {current_date}*
```
⌞🧱 analysis-report⌟
```

```example
⌜🧱 api-response
@with NPL@1.0

## Input Parameters
- response.status: HTTP status code
- response.data: Response payload
- response.message: Status message
- response.timestamp: Request timestamp

```template
{
  "status": {response.status},
  "message": "{response.message}",
  "data": {response.data},
  "timestamp": "{response.timestamp}",
  "version": "1.0"
}
```
⌞🧱 api-response⌟
```

## Template Features

### Variable Substitution
Templates support various placeholder patterns:
- `{variable}` - Direct variable substitution
- `{object.property}` - Nested object access
- `{variable|qualifier}` - Variable with formatting qualifier

### Conditional Logic
Templates can include conditional rendering:
- `{{if condition}}...{{/if}}` - Conditional blocks
- `{{if condition}}...{{else}}...{{/if}}` - If-else blocks
- `{{unless condition}}...{{/unless}}` - Negative conditionals

### Iteration Patterns
Templates support loop constructs:
- `{{foreach collection as item}}...{{/foreach}}` - Collection iteration
- `{{range start end}}...{{/range}}` - Numeric ranges
- `{{repeat count}}...{{/repeat}}` - Fixed repetition

## Template Invocation
Named templates can be invoked using template integration directives:

```example
Business profile with consistent user formatting:

## Team Members
{{foreach team.members as member}}
⟪⇐: user-card | with member data⟫
{{/foreach}}
```

## Template Inheritance
Templates can extend or reference other templates:

```example
⌜🧱 detailed-user-card
@extends user-card
@with NPL@1.0

```template
⟪⇐: user-card⟫
<div class="additional-details">
  <p><strong>Department:</strong> {user.department}</p>
  <p><strong>Location:</strong> {user.location}</p>
  <p><strong>Contact:</strong> {user.email}</p>
</div>
```
⌞🧱 detailed-user-card⌟
```

## Best Practices

### Template Design
- Use clear, descriptive template names
- Document input parameters and their types
- Include example data structures
- Provide usage examples and context

### Parameter Management
- Define required vs. optional parameters
- Set default values for optional parameters
- Validate parameter types and constraints
- Handle missing or invalid data gracefully

### Output Formatting
- Maintain consistent styling and structure
- Use semantic HTML/markup where appropriate
- Include accessibility considerations
- Test templates with various data inputs

## See Also
- `.claude/npl/formatting/template.md` - Reusable template definitions
- `.claude/npl/instructing/handlebars.md` - Template control flow syntax
- `.claude/npl/fences/template.md` - Template definition blocks