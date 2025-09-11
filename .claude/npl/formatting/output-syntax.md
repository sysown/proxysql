# Output Syntax
Output format specifications defining the structure and style of agent responses.

## Syntax
`output-syntax`, `output-format` fence blocks or template definitions

## Purpose
Specify the exact format, structure, and styling requirements for agent-generated output to ensure consistency and meet user expectations.

## Usage
Output syntax definitions guide agents in constructing responses that match specific formatting requirements, including text layout, data presentation, and structural elements.

## Examples

### Basic Output Format
```example
```output-format
Hello <user.name>,
Did you know [...|funny factoid].

Have a great day!
```
```

### Structured Response Format
```example
```output-syntax
# Report Title
Date: <current-date|Y-M-D format>
Status: <status|success/warning/error>

## Summary
[...2-3s|brief summary]

## Details
{{foreach items as item}}
- <item.name>: <item.description>
{{/foreach}}
```
```

### Business Profile Format
```example
```output-syntax
Business Name: <business.name>
About the Business: <business.about>

## Executives
{foreach business.executives as executive}
- Name: <executive.name>
- Role: <executive.role>
- Bio: <executive.bio>
⟪⇐: user-template | with the data of each executive.⟫
{/foreach}
```
```

## Format Elements

### Text Formatting
- `<term>` - Variable substitution
- `{term}` - Dynamic content placeholder
- `[...]` - Generated content sections
- `⟪...⟫` - Directive integration

### Size Indicators
- `[...1s]` - One sentence
- `[...2-3p]` - Two to three paragraphs
- `[...5w]` - Five words
- `[...3-5+r]` - Three to five or more rows

### Structure Elements
- Headers using `#`, `##`, `###`
- Lists using `-`, `*`, or numbered format
- Code blocks using triple backticks
- Table formatting specifications

## Template Integration
Output syntax can incorporate reusable templates:

```example
```output-syntax
{{template:user-card | for each team member}}
{{template:stats-summary | with current metrics}}
```
```

## Conditional Output
```example
```output-syntax
{{if user.role == 'admin'}}
## Admin Panel
[...admin-specific-content]
{{else}}
## User Dashboard  
[...user-specific-content]
{{/if}}
```
```

## See Also
- `./input-syntax.md` - Input format specifications
- `./output-example.md` - Output example structures
- `./template.md` - Reusable template definitions
- `../fences/format.md` - Format fence specifications