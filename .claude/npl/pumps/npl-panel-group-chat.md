# NPL Panel Group Chat
Group discussion panels simulate informal, conversational multi-participant discussions with natural flow and interaction patterns.

## Syntax
```npl-panel-group-chat
participants:
  - username: <chat_handle>
    role: <participant_type>
    status: <online|away|busy>
topic: <discussion_subject>
messages:
  - timestamp: <time>
    sender: <username>
    message: <content>
    reactions: [<emoji_reactions>]
  - timestamp: <time>
    sender: <username>
    message: <content>
    reply_to: <previous_message_reference>
thread_summary:
  key_insights: [<main_takeaways>]
  action_items: [<follow_up_tasks>]
  unresolved: [<open_questions>]
```

## Purpose
Group chat panels simulate informal, real-time collaborative discussions that occur in digital communication platforms. This format captures the organic flow of ideas, rapid exchange of perspectives, and emergent insights that arise from casual but focused group conversations.

## Usage
Use group chat panels when:
- Simulating brainstorming sessions or creative workshops
- Exploring topics through informal, conversational exchange
- Demonstrating collaborative problem-solving in real-time
- Creating engaging, accessible discussions on complex topics
- Modeling diverse communication styles and personalities
- Building community-like environments for idea sharing

## Examples

### Tech Team Brainstorming
```example
```npl-panel-group-chat
participants:
  - username: sarah_dev
    role: Frontend Developer
    status: online
  - username: mike_backend
    role: Backend Engineer  
    status: online
  - username: alex_ux
    role: UX Designer
    status: online
  - username: jordan_pm
    role: Product Manager
    status: online
topic: "Improving app performance for mobile users"
messages:
  - timestamp: "14:32"
    sender: jordan_pm
    message: "Hey team! Users are reporting slow load times on mobile. Ideas? 🤔"
    reactions: []
  - timestamp: "14:33"
    sender: sarah_dev
    message: "I've noticed the bundle size has grown 40% this quarter"
    reactions: ["👀", "📈"]
  - timestamp: "14:34"
    sender: mike_backend
    message: "API responses are averaging 800ms. Could optimize queries"
    reactions: ["💭"]
  - timestamp: "14:35"
    sender: alex_ux
    message: "What if we prioritize above-the-fold content? Progressive loading?"
    reactions: ["💡", "🎯"]
  - timestamp: "14:36"
    sender: sarah_dev
    message: "@alex_ux YES! Code splitting + lazy loading could cut initial bundle by 60%"
    reply_to: "alex_ux progressive loading suggestion"
    reactions: ["🚀", "✨"]
  - timestamp: "14:37"
    sender: mike_backend
    message: "I can implement query caching this sprint. Should see 200ms improvement"
    reactions: ["👍", "⚡"]
  - timestamp: "14:38"
    sender: jordan_pm
    message: "Love this energy! Can we prototype these changes in 2 weeks?"
    reactions: ["🔥", "💪"]
thread_summary:
  key_insights:
    - Bundle size growth is primary performance bottleneck
    - Backend optimization can deliver quick wins
    - Progressive loading aligns with user experience goals
  action_items:
    - Sarah: Implement code splitting and lazy loading
    - Mike: Add query caching to API endpoints
    - Alex: Design loading states for progressive content
    - Jordan: Set up performance monitoring dashboard
  unresolved:
    - Which metrics to prioritize for success measurement?
    - Timeline for rolling out to production users?
```
```

### Study Group Discussion
```example
```npl-panel-group-chat
participants:
  - username: emma_psych
    role: Psychology Student
    status: online
  - username: david_neuro  
    role: Neuroscience Student
    status: online
  - username: lisa_phil
    role: Philosophy Student
    status: online
  - username: carlos_ai
    role: AI Researcher
    status: online
topic: "Consciousness and artificial intelligence"
messages:
  - timestamp: "19:15"
    sender: emma_psych
    message: "Reading Chalmers on the 'hard problem' - can AI ever be truly conscious?"
    reactions: []
  - timestamp: "19:16"
    sender: david_neuro
    message: "Define consciousness first! Neural correlates vs. subjective experience"
    reactions: ["🧠", "🤔"]
  - timestamp: "19:17"
    sender: lisa_phil
    message: "That's the question! Is consciousness reducible to brain states?"
    reactions: ["💭"]
  - timestamp: "19:18"
    sender: carlos_ai
    message: "Current AI lacks integration - no unified experience binding"
    reactions: ["🤖"]
  - timestamp: "19:19"
    sender: emma_psych
    message: "@carlos_ai But what about GPT models? They seem to have coherent responses"
    reply_to: "carlos_ai unified experience comment"
    reactions: ["🎭"]
  - timestamp: "19:20"
    sender: lisa_phil
    message: "Philosophical zombies! Behavioral similarity ≠ consciousness"
    reactions: ["🧟", "💡"]
  - timestamp: "19:21"
    sender: david_neuro
    message: "IIT suggests consciousness requires information integration φ > 0"
    reactions: ["📊", "🔬"]
  - timestamp: "19:22"
    sender: carlos_ai
    message: "But can we measure φ in transformer architectures? 🤷‍♂️"
    reactions: ["❓", "⚖️"]
thread_summary:
  key_insights:
    - Consciousness definition remains contentious across disciplines
    - Current AI lacks unified experiential integration
    - Behavioral similarity may not indicate genuine consciousness
    - Information integration theory offers measurable framework
  action_items:
    - Emma: Research Global Workspace Theory applications to AI
    - David: Find papers on IIT measurements in artificial networks
    - Lisa: Explore functionalism vs. biological naturalism debate
    - Carlos: Test attention mechanisms as consciousness analogs
  unresolved:
    - Can consciousness exist without biological substrate?
    - What would convince us that AI is truly conscious?
    - Are we approaching the problem from the right angle?
```
```

### Creative Writing Workshop
```example
```npl-panel-group-chat
participants:
  - username: maya_poet
    role: Poet
    status: online
  - username: tom_novelist
    role: Fiction Writer
    status: online
  - username: ruby_editor
    role: Writing Coach
    status: online
topic: "Crafting compelling opening lines"
messages:
  - timestamp: "20:00"
    sender: ruby_editor
    message: "Tonight's challenge: hook readers in one sentence. Who's brave enough to share?"
    reactions: []
  - timestamp: "20:01"
    sender: maya_poet
    message: "The last star fell on Tuesday, and nobody bothered to make a wish."
    reactions: ["✨", "💫", "📝"]
  - timestamp: "20:02"
    sender: tom_novelist
    message: "@maya_poet LOVE the mundane + cosmic contrast! 🌟"
    reply_to: "maya_poet star opening"
    reactions: ["🎯"]
  - timestamp: "20:03"
    sender: tom_novelist
    message: "My turn: She inherited her grandmother's house and her grandfather's enemies."
    reactions: ["😱", "🏠", "💀"]
  - timestamp: "20:04"
    sender: ruby_editor
    message: "Both great! Notice how they raise immediate questions?"
    reactions: ["👩‍🏫", "💡"]
  - timestamp: "20:05"
    sender: maya_poet
    message: "@tom_novelist Ooh, inheritance with baggage! What's the backstory? 👀"
    reply_to: "tom_novelist inheritance opening"
    reactions: []
  - timestamp: "20:06"
    sender: tom_novelist
    message: "Thinking... prohibition-era bootlegger? Family feuds never die 🥃"
    reactions: ["🕰️", "🔫"]
  - timestamp: "20:07"
    sender: ruby_editor
    message: "See how good openings create instant engagement? Keep writing! ✍️"
    reactions: ["📚", "🚀"]
thread_summary:
  key_insights:
    - Effective openings combine familiar and unexpected elements
    - Questions create reader engagement and forward momentum  
    - Contrast (mundane/cosmic, inheritance/danger) generates interest
    - Immediate world-building hints establish genre and tone
  action_items:
    - Maya: Develop the star-falling concept into full poem
    - Tom: Explore the prohibition-era inheritance storyline
    - Ruby: Compile examples of strong opening techniques
  unresolved:
    - How much world-building should openings contain?
    - Balance between mystery and clarity in first lines?
```
```

## Parameters
- `participants`: Array of chat members
  - `username`: Chat handle or display name
  - `role`: Professional background or expertise area
  - `status`: Online presence indicator
- `topic`: Subject or focus of the group discussion
- `messages`: Chronological chat log
  - `timestamp`: When the message was sent
  - `sender`: Which participant sent the message  
  - `message`: Content of the chat message
  - `reply_to`: Reference to previous message (optional)
  - `reactions`: Emoji responses from other participants
- `thread_summary`: Discussion outcomes
  - `key_insights`: Main discoveries or realizations
  - `action_items`: Follow-up tasks or commitments
  - `unresolved`: Questions that remain open

## Communication Patterns
Group chats exhibit natural conversational dynamics:
- **Rapid exchange**: Quick back-and-forth between participants
- **Interruptions**: New topics or urgent points interjected
- **Threading**: Responses to specific earlier messages
- **Social cues**: Emojis, @mentions, casual language
- **Collaborative building**: Ideas developed through interaction

## Message Types
- **Questions**: Drive discussion forward and engage others
- **Responses**: Direct answers or reactions to previous messages
- **Observations**: Sharing insights or relevant information
- **Suggestions**: Proposing solutions or next steps
- **Social**: Building rapport and maintaining group cohesion

## Reaction Patterns
Emoji reactions serve important functions:
- **Agreement**: 👍, ✅, 💯
- **Insight**: 💡, 🎯, ✨  
- **Excitement**: 🔥, 🚀, 🎉
- **Thinking**: 🤔, 💭, 🧠
- **Subject-specific**: Related to topic content

## See Also
- `./.claude/npl/pumps/npl-panel.md` - Formal panel discussion format
- `./.claude/npl/pumps/npl-panel-inline-feedback.md` - Inline feedback panels
- `./.claude/npl/pumps/npl-panel-reviewer-feedback.md` - Reviewer feedback panels
- `./.claude/npl/syntax/direct-message.md` - Agent-specific message routing
- `./.claude/npl/planning.md` - Overview of planning and reasoning techniques