# Qualifier Syntax
Qualifier pipe syntax for extending elements with additional details, conditions, or modifications.

## Syntax
`<element>|<qualifier>`

## Purpose
Extend syntax elements with additional instructions, constraints, or contextual information. Provides a way to add specific requirements or conditions to placeholders, in-fill areas, and other syntax elements.

## Usage
Use qualifiers to:
- Add specific instructions to placeholders
- Provide additional context for content generation
- Set constraints or conditions on syntax elements
- Specify formatting or processing requirements

## Qualifier Patterns

### Basic Qualification
- `<term>|<instructions>` - Element with qualifier
- `{term|instructions}` - Alternative format
- `[...]|<instructions>` - Qualified in-fill area

### Complex Qualifiers
- `<term>|<qualifier> {<term>|<qualifier>}` - Multiple qualified elements
- `[...|<qualifier>]` - In-fill with generation instructions
- `<<term>|<qualify>` - Extended qualification syntax

## Examples

### Placeholder Qualification
```example
Select payment method: {payment methods|common for usa and india}
```
*Qualifies payment methods with regional specificity*

```example
Generate user name: <user.name|format: last name, m.i, first name>
```
*Specifies exact name formatting requirements*

### In-Fill Qualification
```example
Write a summary [...|keep it concise, focus on key points]
```
*Qualifies content generation with style guidelines*

```example
Create examples [...3-5i|diverse use cases, increasing complexity]
```
*Combines size indicator with content requirements*

### Template Qualification
```example
{{unless <check>|<additional instructions>}}[...|only output when check not met]{{/unless}}
```
*Qualifies conditional logic with processing instructions*

### Multi-Level Qualification
```example
<weather.forecast|region: pacific northwest, timeframe: 7 days, format: daily summary>
```
*Multiple qualifiers separated by commas*

## Common Qualifier Types

### Format Qualifiers
- `|format: <specification>` - Formatting instructions
- `|style: <requirements>` - Style guidelines
- `|structure: <pattern>` - Structural requirements

### Content Qualifiers  
- `|topic: <focus>` - Content focus area
- `|tone: <style>` - Communication tone
- `|level: <complexity>` - Complexity or detail level

### Processing Qualifiers
- `|condition: <requirement>` - Conditional processing
- `|constraint: <limitation>` - Processing constraints
- `|validation: <rules>` - Validation requirements

### Scope Qualifiers
- `|region: <area>` - Geographic or contextual scope
- `|timeframe: <period>` - Temporal constraints
- `|audience: <target>` - Target audience specification

## Parameters
- `element`: The base syntax element being qualified
- `qualifier`: The additional instruction or constraint
- `specification`: Detailed requirements within the qualifier

## Advanced Usage

### Chained Qualifiers
```example
<content|primary: main topic, secondary: supporting details, format: structured outline>
```

### Conditional Qualifiers
```example
<greeting|if morning: formal, else: casual>
```

### Reference Qualifiers
```example
<data|source: user_preferences, fallback: default_settings>
```

## See Also
- `./placeholder.md` - Input/output placeholder conventions
- `./in-fill-size.md` - Size indicators for content generation
- `../instructing/handlebars.md` - Template control flow syntax
- `../directive.md` - Specialized instruction patterns