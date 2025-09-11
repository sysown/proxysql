# Response Mode Indicators
Prefix patterns that control agent output modes and response behaviors using emoji-based indicators.

## Syntax
`emoji➤ <instruction or content>`

## Purpose
Response mode indicators use the `emoji➤` pattern to signal specific output formats, processing contexts, and behavioral modifications for agents. These prefixes shape how content is generated, structured, and presented.

## Usage
Place prefix indicators at the beginning of sections, prompts, or messages to specify the desired response mode. Prefixes can also be used inline with agent references: `@emoji➤{agent}`

## Core Prefix Patterns

### Conversational Interaction
**👪➤** - Engage in dialogue or conversational response
```example
👪➤ Simulate a conversation where a customer is inquiring about their order status.
```

### Visual Content
**🖼️➤** - Generate image captions or visual descriptions
```example
🖼️➤ Write a caption for this image of a mountainous landscape at sunset.
```

### Audio Processing
**🔊➤** - Text-to-speech synthesis instructions
```example
🔊➤ Convert the following sentence into spoken audio format.
```

**🗣️➤** - Speech recognition or transcription tasks
```example
🗣️➤ Transcribe the following audio clip of a conversation.
```

### Information Retrieval
**❓➤** - Direct question answering format
```example
❓➤ What is the tallest mountain in the world?
```

**📊➤** - Topic modeling and analysis
```example
📊➤ Determine the prevalent topics across a collection of research papers.
```

### Language Processing
**🌐➤** - Machine translation tasks
```example
🌐➤ Translate the following sentences from English to Spanish.
```

**👁️➤** - Named entity recognition
```example
👁️➤ Locate and categorize named entities in this article excerpt.
```

### Content Generation
**🖋️➤** - Creative text generation
```example
🖋️➤ Write an opening paragraph for a story set in a futuristic city.
```

**🖥️➤** - Code generation and programming
```example
🖥️➤ Define a Python function that takes two parameters and returns their sum.
```

### Content Analysis
**🏷️➤** - Text classification tasks
```example
🏷️➤ Categorize the following support ticket into the correct department.
```

**💡➤** - Sentiment analysis
```example
💡➤ Assess the sentiment of this customer product review.
```

**📄➤** - Text summarization
```example
📄➤ Provide a summary of the main points from this news article.
```

**🧪➤** - Feature extraction and data analysis
```example
🧪➤ Extract the highest and lowest temperatures from this week's weather data.
```

### Specialized Patterns
**🗣️❓➤** - Word puzzles and riddles
```example
🗣️❓➤ Nothing in the dictionary starts with an n and ends in a g
```

## Behavior Control
Prefixes modify agent behavior by:
- Setting expected output format
- Activating specialized processing modes
- Triggering domain-specific capabilities
- Defining interaction patterns

## Precedence Rules
- Response-level prefixes override agent defaults
- Multiple prefixes can be combined for complex behaviors
- Later prefixes in a chain take precedence over earlier ones

## Parameters
- **emoji**: Visual indicator defining the response mode
- **instruction**: Specific guidance for content generation
- **qualifier**: Optional additional constraints using `|` syntax

## See Also
- `./npl/prefix/*` - Individual prefix documentation
- `./npl/directive.md` - Specialized instruction widgets
- `./npl/syntax/placeholder.md` - Placeholder conventions
- `./npl/agent.md` - Agent behavior modification