# Value Placeholder
Dynamic content injection points that specify where agents should insert specific content in output or indicate expected input locations.

## Syntax  
`⟪input/output placeholder to be received or generated⟫`  
`{...}`  
`<...>`

## Purpose
Value placeholders serve as dynamic content injection points that direct agents to insert specific content at defined locations in output, or to indicate where input is expected. This enables personalized, contextual, and template-driven response generation.

## Usage
Use value placeholders when you need to:
- Personalize output with user-specific information
- Create template-driven responses with variable content
- Indicate expected input locations in prompts
- Generate contextually appropriate content at specific points

## Examples

### User Information Injection
```example
Hello ⟪user.name⟫, welcome back to the system!
```
The agent replaces `⟪user.name⟫` with the actual user's name in the output.

### Formatted Name Display
```example
Hello {user.name | format: last name, m.i, first name}, welcome back!
```
Applies formatting rules to display the user's name in a specific format (last name, middle initial, first name).

### Basic Content Placeholder
```example
The weather today is <temperature> degrees with <conditions>.
```
Indicates where temperature and weather condition data should be inserted.

### Conditional Content
```example
Your account balance is {user.balance | currency: USD}.
```
Displays the user's account balance formatted as USD currency.

## Parameters
- `content`: The data reference or description of what should be injected
- `qualifier`: Optional formatting or processing instructions (using `|` separator)

## Placeholder Formats
- `⟪...⟫`: Primary NPL placeholder syntax for explicit content injection
- `{...}`: Template-style placeholders, often with formatting options
- `<...>`: Simple angle-bracket placeholders for basic content insertion

## Advanced Features
### Formatting with Qualifiers
```example
⟪user.joinDate | format: YYYY-MM-DD⟫
{product.price | currency: EUR | precision: 2}
```

### Conditional Logic
```example
⟪user.membershipLevel | if premium then "Premium Member" else "Standard Member"⟫
```

## See Also
- `./qualifier.md` - Qualifier pipe syntax for content modification
- `./../../directive.md` - Specialized directive placeholders
- `./../../formatting/template.md` - Advanced template placeholder patterns