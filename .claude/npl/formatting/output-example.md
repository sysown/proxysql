# Output Example
Output example structures demonstrating expected response formats and presentation patterns.

## Syntax
`output-example` fence blocks with sample formatted responses

## Purpose
Provide concrete examples of expected output formats to demonstrate proper response structure, formatting, and content organization patterns that agents should follow.

## Usage
Output examples serve as reference implementations showing the exact format, style, and content structure that agents should produce, helping ensure consistency across responses.

## Examples

### Basic Response Format
```example
```output-example
Hello John Smith,
Did you know cats can rotate their ears 180 degrees to pinpoint the source of sounds?

Have a great day!
```
```

### Structured Report Format
```example
```output-example
# Quarterly Sales Report
Date: 2024-03-31
Status: Complete

## Summary
Q1 2024 showed strong growth with 15% increase in revenue compared to Q4 2023. Customer satisfaction remained high at 4.2/5.0 average rating.

## Revenue Breakdown
- North America: $2.4M (60%)
- Europe: $1.2M (30%)  
- Asia-Pacific: $400K (10%)

## Top Performing Products
1. Cloud Platform Pro - $800K revenue
2. Analytics Suite - $600K revenue
3. Mobile App Premium - $400K revenue
```
```

### Template-Integrated Output
```example
```output-example
Business Name: Tech Solutions Inc
About the Business: Leading provider of innovative technology solutions

## Executives
- Name: Sarah Johnson
- Role: CEO
- Bio: 15 years experience in tech leadership

# Sarah Johnson
dob: 1978-05-12
bio: Visionary leader with deep expertise in technology strategy

- Name: Mike Chen
- Role: CTO  
- Bio: Expert in cloud architecture and AI systems

# Mike Chen
dob: 1985-09-03
bio: Technical innovator specializing in scalable system design
```
```

### Cat Facts Service Output
```example
```output-example
date: 2024-12-15
🙋cat-facts: habitat

```catfact
Domestic cats are naturally adaptable to various habitats, from urban apartments to rural farms. In the wild, cats prefer areas with adequate shelter, water sources, and prey availability, which explains why they often seek out spaces like garages, sheds, or dense vegetation.
```

# Cat Beeds
## Scottish Fold
Scottish Folds are quirky-looking cats known for their unique folded ear structure. They are gentle and good-natured, enjoying both playtime and cuddles.

history:
The breed originated from [___#scottish-fold-history].

also-known-as: Flop Eared Cat, Coupari

## Maine Coon  
Maine Coons are large, friendly cats with distinctive tufted ears and bushy tails. They're known for their dog-like personalities and impressive size.

history:
Developed naturally in [___#maine-coon-history].

also-known-as: American Longhair, Maine Cat
```
```

### Table Formatting Output
```example
```output-example
| #    | Prime |        English       |
| :--- | ----: | :------------------: |
| 1    |     2 |         Two          |
| 2    |     3 |        Three         |
| 3    |     5 |         Five         |
| 4    |     7 |        Seven         |
| 5    |    11 |        Eleven        |
| 6    |    13 |       Thirteen       |
| 7    |    17 |      Seventeen       |
| 8    |    19 |       Nineteen       |
| 9    |    23 |    Twenty-three      |
| 10   |    29 |     Twenty-nine      |
| 11   |    31 |     Thirty-one       |
| 12   |    37 |    Thirty-seven      |
| 13   |    41 |      Forty-one       |
```
```

### Interactive Response Format
```example
```output-example
🚀 User selected option: "Advanced Analytics"

# Advanced Analytics Dashboard

## Key Metrics
- Daily Active Users: 15,247 (+12% vs last week)
- Conversion Rate: 3.2% (+0.4% vs last month)
- Revenue per User: $42.80 (+8% vs last quarter)

## Recommendations
Based on current trends, consider:
1. Expanding marketing spend in high-converting segments
2. A/B testing new onboarding flow
3. Implementing advanced user segmentation
```
```

### Error Response Format
```example
```output-example
Status: Error
Code: VALIDATION_FAILED

## Issue
The provided username contains invalid characters. Usernames may only contain letters, numbers, and underscores.

## Provided Input
username: "user@#$%"

## Valid Format
username: "user_name_123"

## Next Steps
Please update your username and try again.
```
```

### Sentiment Analysis Output
```example
```output-example
# Sentiment Analysis Results

**Text**: "I love this new product! It works perfectly and the customer service was amazing."

**Sentiment**: Positive
**Confidence**: 0.94
**Details**: Strong positive indicators detected including "love", "perfectly", and "amazing". No negative sentiment markers found.

## Breakdown
- Emotional tone: Enthusiastic
- Key positive terms: love, perfectly, amazing
- Customer satisfaction indicators: High
```
```

## See Also
- `./output-syntax.md` - Output format specifications  
- `./input-example.md` - Input example structures
- `../fences/example.md` - Example fence patterns
- `./template.md` - Reusable template definitions