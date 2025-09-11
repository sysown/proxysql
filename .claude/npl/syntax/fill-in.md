# Fill-In
Content generation area markers that signal specific locations where dynamic content should be generated or expected sections should be omitted for brevity.

## Syntax
`[...]` - Basic fill-in  
`[...| details]` - Detailed fill-in with qualifiers  
`[... <details> ...]` - Alternative detailed fill-in  
`[...p]` - Parameterized fill-in

## Purpose
Fill-in markers indicate areas in prompts where dynamic content generation should occur or where expected sections can be omitted for brevity while maintaining structural clarity. This enables flexible template creation and content scaffolding.

## Usage
Use fill-in markers when you need to:
- Designate areas for dynamic content generation
- Create template structures with variable sections
- Indicate where contextually appropriate content should be inserted
- Omit repetitive or expected content for prompt efficiency

## Examples

### Basic Dynamic Generation
```example
The event will feature several keynote speakers including [...].
```
Agent generates an appropriate list of speakers relevant to the event context.

### Qualified Content Generation
```example
The research methodology section should cover [...|standard research approaches for qualitative studies].
```
Agent fills in with methodologies specific to qualitative research.

### Alternative Qualification Style
```example
Implementation details [... security considerations, performance optimizations ...] will be addressed.
```
Agent expands on security and performance aspects of implementation.

### Parameterized Fill-In
```example
Database configuration options [...p] can be customized based on requirements.
```
Agent generates parameter-specific configuration options.

### Multiple Fill-In Areas
```example
The project timeline includes:
- Phase 1: Planning [...|2 weeks]
- Phase 2: Development [...|6 weeks] 
- Phase 3: Testing [...|2 weeks]
```
Agent fills in activities appropriate to each phase duration.

## Fill-In Types

### Content Generation Fill-In
```example
Popular vacation destinations include [...].
```
Agent generates contextually appropriate destinations.

### Structural Fill-In  
```example
## Meeting Agenda
1. Opening remarks
2. [...|main discussion topics]
3. Action items
4. Closing
```
Agent fills in relevant discussion topics for the meeting context.

### Technical Fill-In
```example
The API endpoint accepts the following parameters: [...|required and optional parameters with types].
```
Agent generates appropriate parameter documentation.

### Conditional Fill-In
```example
Error handling should include [...|appropriate exception types for this use case].
```
Agent fills in context-specific error handling approaches.

## Qualifier Usage
Fill-in markers can include qualifiers to guide content generation:
- `[...| specific guidance]` - Direct qualifier guidance
- `[... <context> ...]` - Contextual guidance wrapper
- `[...p]` - Parameter-specific content
- `[...n]` - Numbered or sequential content

## Best Practices
- Provide sufficient context for meaningful content generation
- Use qualifiers to guide the type and scope of content needed
- Consider the audience and purpose when structuring fill-in areas
- Balance specificity with flexibility in qualifier descriptions

## See Also
- `./ellipsis-inference.md` - Continuation and pattern inference
- `./qualifier.md` - Qualifier pipe syntax for content modification
- `./in-fill-size.md` - Size indicators for content generation scope
- `./../../formatting/template.md` - Template-based content structures