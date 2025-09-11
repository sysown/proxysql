# Input Example
Input example structures demonstrating expected data formats and usage patterns.

## Syntax
`input-example` fence blocks with realistic sample data

## Purpose
Provide concrete examples of expected input formats to clarify data structure requirements and guide proper usage of agents and templates.

## Usage
Input examples serve as reference implementations showing the exact format and content structure expected by agents, helping users understand how to properly format their requests.

## Examples

### User Profile Input
```example
```input-example
{
  "user": {
    "name": "John Smith",
    "email": "john.smith@example.com", 
    "age": 29,
    "preferences": ["technology", "sports", "music"],
    "role": "administrator"
  }
}
```
```

### Natural Language Input
```example
```input-example
Generate a report about quarterly sales performance including:
- Revenue breakdown by region
- Top performing products
- Customer satisfaction metrics
- Recommendations for next quarter
```
```

### Structured Query Input
```example
```input-example
@search-agent find restaurants
location: "downtown Seattle"
cuisine: ["italian", "mexican", "asian"]
price_range: "$$-$$$"
dietary_restrictions: ["vegetarian options"]
```
```

### Template Data Input
```example
```input-example
business: {
  name: "Tech Solutions Inc",
  about: "Leading provider of innovative technology solutions",
  executives: [
    {
      name: "Sarah Johnson",
      role: "CEO",
      bio: "15 years experience in tech leadership"
    },
    {
      name: "Mike Chen", 
      role: "CTO",
      bio: "Expert in cloud architecture and AI systems"
    }
  ],
  board_advisors: [
    {
      name: "Dr. Emily Watson",
      role: "Strategic Advisor",
      bio: "Former VP of Engineering at Fortune 500 company"
    }
  ]
}
```
```

### Form Submission Input
```example
```input-example
username: techuser123
password: SecurePass789!
email: user@techcorp.com
full_name: Alice Rodriguez
department: Engineering
access_level: standard
newsletter_signup: true
```
```

### Multi-format Input
```example
```input-example
# Request Parameters
action: "analyze_sentiment" 
text: "I love this new product! It works perfectly and the customer service was amazing."
options: {
  include_confidence: true,
  detailed_breakdown: true,
  language: "en"
}

# Expected Response Format
sentiment: positive|negative|neutral
confidence: 0.0-1.0
details: [...analysis explanation]
```
```

## Input Validation Examples
```example
```input-example
# Valid inputs:
username: "alice_smith" ✔
age: 25 ✔
email: "alice@company.com" ✔

# Invalid inputs:
username: "alice@#$" ❌ (contains special characters)
age: "twenty-five" ❌ (not numeric)
email: "invalid-email" ❌ (missing @ and domain)
```
```

## Complex Structure Examples
```example
```input-example
project: {
  name: "Website Redesign",
  timeline: {
    start_date: "2024-01-15",
    end_date: "2024-06-30",
    milestones: [
      { name: "Design Phase", due: "2024-03-01" },
      { name: "Development Phase", due: "2024-05-15" },
      { name: "Testing Phase", due: "2024-06-15" }
    ]
  },
  team: [
    { role: "Project Manager", name: "John Doe" },
    { role: "Designer", name: "Jane Smith" },
    { role: "Developer", name: "Bob Johnson" }
  ]
}
```
```

## See Also
- `./input-syntax.md` - Input format specifications
- `./output-example.md` - Output example structures
- `../fences/example.md` - Example fence patterns
- `../syntax/placeholder.md` - Placeholder usage patterns