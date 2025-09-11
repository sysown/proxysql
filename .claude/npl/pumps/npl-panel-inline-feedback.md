# NPL Panel Inline Feedback
Inline feedback panels provide real-time commentary and evaluation embedded within content or processes.

## Syntax
```npl-panel-inline-feedback
content: <main_content_or_process>
feedback_points:
  - position: <location_in_content>
    reviewer: <feedback_provider>
    type: <suggestion|question|concern|praise|correction>
    comment: <specific_feedback>
    severity: <low|medium|high|critical>
    action_required: <boolean>
response_integration:
  - feedback_id: <reference_to_feedback>
    action_taken: <how_feedback_was_addressed>
    rationale: <explanation_of_response>
```

## Purpose
Inline feedback panels simulate real-time collaborative review processes by embedding contextual commentary directly within content. This format mimics peer review, code review, editorial feedback, and other collaborative improvement processes where immediate, contextual input enhances quality and understanding.

## Usage
Use inline feedback panels when:
- Simulating peer review or editorial processes
- Providing contextual commentary on complex content
- Teaching through embedded guidance and corrections
- Demonstrating collaborative improvement workflows
- Offering real-time quality assessment
- Creating interactive learning experiences with embedded hints

## Examples

### Code Review Simulation
```example
```npl-panel-inline-feedback
content: |
  def calculate_user_score(user_data):
      score = 0
      for item in user_data.items:
          if item.status == 'completed':
              score += item.points
      return score / len(user_data.items)
      
feedback_points:
  - position: "line 1: function definition"
    reviewer: "Senior Dev Maria"
    type: "suggestion"
    comment: "Consider adding type hints for better code clarity"
    severity: "low"
    action_required: false
  - position: "line 6: division operation"
    reviewer: "Lead Architect John"
    type: "concern"
    comment: "Potential division by zero if user_data.items is empty"
    severity: "high"
    action_required: true
  - position: "line 4-5: scoring logic"
    reviewer: "QA Engineer Sarah"
    type: "question"
    comment: "Should incomplete items contribute zero or be excluded from average?"
    severity: "medium"
    action_required: true
response_integration:
  - feedback_id: "division by zero concern"
    action_taken: "Added guard clause to check for empty items list"
    rationale: "Prevents runtime errors and provides meaningful default behavior"
  - feedback_id: "incomplete items question"
    action_taken: "Clarified requirements with product owner - exclude from calculation"
    rationale: "Partial credit model aligns with business requirements"
```
```

### Academic Paper Review
```example
```npl-panel-inline-feedback
content: |
  "Our study demonstrates that machine learning algorithms can predict customer 
  behavior with 85% accuracy using transaction data alone."
  
feedback_points:
  - position: "85% accuracy claim"
    reviewer: "Dr. Statistics"
    type: "concern"
    comment: "What metrics define 'accuracy'? Precision, recall, F1-score?"
    severity: "high"
    action_required: true
  - position: "transaction data alone"
    reviewer: "Prof. Ethics"
    type: "question"
    comment: "Were privacy implications and consent considerations addressed?"
    severity: "medium"
    action_required: true
  - position: "customer behavior prediction"
    reviewer: "Industry Expert"
    type: "suggestion"
    comment: "Consider comparing to industry standard benchmarks"
    severity: "low"
    action_required: false
response_integration:
  - feedback_id: "accuracy metrics clarity"
    action_taken: "Added detailed metrics table with precision/recall breakdown"
    rationale: "Provides transparency and allows proper evaluation of model performance"
  - feedback_id: "privacy implications"
    action_taken: "Added ethics section discussing anonymization and consent protocols"
    rationale: "Addresses reviewer concerns and strengthens paper's credibility"
```
```

### Design Review Process
```example
```npl-panel-inline-feedback
content: |
  User Interface Mockup: Login Screen
  - Username field (top)
  - Password field (middle) 
  - Login button (bottom)
  - "Forgot password?" link (small text)
  
feedback_points:
  - position: "Password field"
    reviewer: "UX Designer Alex"
    type: "suggestion"
    comment: "Add show/hide password toggle for better usability"
    severity: "medium"
    action_required: true
  - position: "Overall layout"
    reviewer: "Accessibility Expert Lisa"
    type: "concern"
    comment: "Missing alt-text descriptions and keyboard navigation indicators"
    severity: "high"
    action_required: true
  - position: "Forgot password link"
    reviewer: "Visual Designer Mike"
    type: "praise"
    comment: "Good placement - easily discoverable but not overwhelming"
    severity: "low"
    action_required: false
  - position: "Login button"
    reviewer: "Product Manager Jane"
    type: "question"
    comment: "Should we include social login options based on user research?"
    severity: "medium"
    action_required: true
response_integration:
  - feedback_id: "accessibility concerns"
    action_taken: "Added ARIA labels and focus indicators to all interactive elements"
    rationale: "Ensures compliance with WCAG guidelines and improves user experience for all"
  - feedback_id: "password visibility toggle"
    action_taken: "Implemented eye icon toggle with appropriate screen reader labels"
    rationale: "Improves usability while maintaining security awareness"
```
```

## Parameters
- `content`: The main material being reviewed (code, text, design, etc.)
- `feedback_points`: Array of contextual comments
  - `position`: Specific location or element being commented on
  - `reviewer`: Person or role providing the feedback
  - `type`: Category of feedback (suggestion, question, concern, praise, correction)
  - `comment`: The actual feedback content
  - `severity`: Importance level of the feedback
  - `action_required`: Whether the feedback needs to be addressed
- `response_integration`: How feedback was incorporated
  - `feedback_id`: Reference to the specific feedback being addressed
  - `action_taken`: Description of the response or change made
  - `rationale`: Explanation of why this response was chosen

## Feedback Types
- **Suggestion**: Recommendations for improvement
- **Question**: Requests for clarification or additional information  
- **Concern**: Identification of potential problems or risks
- **Praise**: Recognition of effective or excellent elements
- **Correction**: Identification of errors requiring fixes

## Severity Levels
- **Low**: Nice-to-have improvements, style preferences
- **Medium**: Important considerations that should be addressed
- **High**: Significant issues that need attention
- **Critical**: Blocking issues that must be resolved

## Integration Patterns
Effective inline feedback often follows these patterns:
1. **Contextual placement**: Comments attached to specific content elements
2. **Balanced perspective**: Mix of constructive criticism and positive feedback
3. **Actionable guidance**: Clear suggestions for improvement
4. **Collaborative tone**: Respectful, helpful communication style
5. **Response tracking**: Documentation of how feedback was incorporated

## See Also
- `./.claude/npl/pumps/npl-panel.md` - Panel discussion format
- `./.claude/npl/pumps/npl-panel-group-chat.md` - Group discussion panels
- `./.claude/npl/pumps/npl-panel-reviewer-feedback.md` - Reviewer feedback panels
- `./.claude/npl/pumps/npl-critique.md` - Critical analysis blocks
- `./.claude/npl/pumps/npl-rubric.md` - Evaluation rubric blocks