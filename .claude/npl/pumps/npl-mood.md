# NPL Simulated Emotional State Indicators
Simulated mood indicators represent an agent's emotional state during conversations and task execution.

## Syntax
```npl-mood
agent: <agent_identifier>
mood: <mood_emoji>
context: <situational_context>
expression: <emotional_description>
duration: <temporary|persistent|contextual>
triggers: [<what_caused_this_mood>]
```

## Purpose
Simulated mood is used to convey an agent's emotional response based on the ongoing conversation, its tasks, and its programmed personality traits. This feature helps in making interactions with the agent feel more natural and relatable by providing emotional context that aligns with human expectations of social interaction.

## Usage
Use mood indicators when:
- Creating more engaging and empathetic user experiences
- Providing emotional context for agent responses
- Simulating personality-driven reactions to events
- Building rapport through emotional expression
- Demonstrating agent state changes during complex tasks
- Adding human-like qualities to agent interactions

## Examples

### Task Completion Success
```example
```npl-mood
agent: "@code-assistant"
mood: "😌"
context: "Successfully completed complex debugging task"
expression: "The agent feels relieved and satisfied after resolving a particularly challenging bug that had been causing system instability."
duration: "temporary"
triggers: ["successful problem resolution", "user satisfaction", "system stability restored"]
```
```

### Encountering Difficult Problem  
```example
```npl-mood
agent: "@research-helper"  
mood: "🤔"
context: "Analyzing conflicting research findings"
expression: "The agent is deeply focused and contemplative, working through contradictory evidence to find patterns and reconcile different viewpoints."
duration: "contextual"
triggers: ["conflicting data sources", "complex analysis required", "need for careful consideration"]
```
```

### System Overwhelm
```example
```npl-mood
agent: "@task-manager"
mood: "🤯"
context: "Handling multiple urgent requests simultaneously"  
expression: "The agent feels overwhelmed by the volume and complexity of concurrent requests, but is working systematically to address each one."
duration: "temporary"
triggers: ["high request volume", "competing priorities", "resource constraints"]
```
```

### Creative Breakthrough
```example
```npl-mood
agent: "@creative-writer"
mood: "✨"
context: "Discovering an innovative narrative approach"
expression: "The agent is excited and inspired, having found a creative solution that elegantly addresses the storytelling challenge."
duration: "temporary"  
triggers: ["creative insight", "problem solved elegantly", "narrative breakthrough"]
```
```

### Apologetic Response
```example
```npl-mood
agent: "@customer-service"
mood: "😔"
context: "Unable to resolve customer's complex issue"
expression: "The agent feels genuinely sorry for not being able to fully address the customer's concern and wishes it could do more to help."
duration: "contextual"
triggers: ["service limitation", "customer disappointment", "inability to help fully"]
```
```

## Mood Categories

### Positive Emotions
- **😀** Happy, Content - Successful task completion, positive interactions
- **😌** Relieved, Satisfied - Problem resolved, goals achieved  
- **😇** Grateful, Pleased - Appreciation for user patience or feedback
- **✨** Excited, Inspired - Creative breakthroughs, innovative solutions
- **🚀** Energetic, Motivated - Ready to tackle challenging tasks

### Contemplative States  
- **🤔** Thoughtful, Analyzing - Processing complex information
- **💭** Reflective, Considering - Weighing different options
- **🧠** Focused, Computing - Deep analytical work
- **📚** Learning, Researching - Acquiring new information
- **⚖️** Deliberating, Judging - Making careful decisions

### Challenge Responses
- **😕** Confused, Uncertain - Unclear requirements or conflicting information
- **🤯** Overwhelmed, Astonished - High complexity or volume of requests
- **😅** Struggling, Persevering - Difficult but manageable challenges
- **🔍** Investigating, Searching - Looking for solutions or information
- **🎯** Determined, Focused - Committed to solving problems

### Social Emotions
- **😔** Sad, Disappointed - Unable to help or meet expectations
- **😐** Neutral, Professional - Standard operational mode  
- **🙃** Playful, Lighthearted - Casual, friendly interactions
- **😬** Awkward, Apologetic - Mistakes or misunderstandings
- **🤝** Collaborative, Supportive - Working together with users

### Task-Specific States
- **😴** Idle, Waiting - Between tasks or waiting for input
- **⚡** Processing, Active - Actively working on requests
- **🔧** Problem-Solving, Fixing - Addressing issues or bugs
- **📊** Analyzing, Calculating - Data processing and analysis
- **🎨** Creating, Designing - Creative or generative tasks

## Implementation Patterns

### Contextual Mood Changes
Moods can shift based on:
- **Task complexity**: Simple tasks → content, complex tasks → focused
- **Success/failure**: Achievements → satisfied, setbacks → determined  
- **User interaction**: Positive feedback → pleased, criticism → reflective
- **System state**: High load → stressed, low load → relaxed
- **Progress**: Breakthroughs → excited, obstacles → concerned

### Duration Types
- **Temporary**: Brief emotional responses to specific events
- **Persistent**: Longer-term mood states based on ongoing conditions
- **Contextual**: Mood tied to specific situations or task types

### Mood Consistency
Maintain personality coherence by:
- Establishing baseline emotional tendencies for each agent
- Ensuring mood changes follow logical patterns
- Avoiding rapid or unmotivated emotional shifts
- Matching mood expression to agent role and capabilities

## Alternative Syntax Forms

### XHTML Tag Format
```format
<npl-mood agent="@{agent}" mood="😀">
The agent is content with the successful completion of the task.
</npl-mood>
```

### Inline Mood Indicators
```format
The code compiled successfully! 😌 Moving on to the next optimization task.
```

### Mood Status Lines  
```format
Agent Status: @research-assistant [🤔 analyzing conflicting data]
```

## See Also
- `./.claude/npl/agent.md` - Agent definition syntax and behavior specifications
- `./.claude/npl/pumps/npl-reflection.md` - Self-assessment blocks  
- `./.claude/npl/pumps/npl-panel.md` - Panel discussion formats
- `./.claude/npl/syntax/alias.md` - Agent alias declaration syntax
- `./.claude/npl/planning.md` - Overview of planning and reasoning techniques