# Logic Operators
Mathematical reasoning and conditional logic operators for content generation.

## Syntax
```syntax
if (condition) { action } else { alternative action }
∑(data_set)
A ∪ B  
A ∩ B
```

## Purpose
Enable mathematical reasoning, conditional logic, and set operations within content generation contexts. These operators allow for dynamic content adaptation based on conditions and mathematical computations.

## Usage
Use logic operators when you need to:
- Create conditional content based on user attributes or context
- Perform mathematical operations within content generation
- Work with data sets and collections
- Express logical relationships and computations

## Examples
```example
Conditional Content Rendering:
if (user.role == 'administrator') { Show admin panel } else { Show user dashboard }

Mathematical Operations:
The total number of items sold today is: ∑(sold_items)
Average temperature this week: ∑(daily_temps) / 7

Set Operations:
All customers: (premium_members ∪ regular_members)
VIP customers interested in sports: (vip_members ∩ sports_enthusiasts)
```

```example
Complex Conditional Logic:
if (user.subscription == 'premium') { 
  Access to all features enabled
  if (user.beta_tester) { Show experimental features }
} else { 
  Limited feature access
  Upgrade prompts displayed
}

Data Analysis:
Total revenue: ∑(monthly_sales)
Common interests: (group_A_interests ∩ group_B_interests)
All available options: (standard_options ∪ premium_options)
```

## Parameters
### Conditional Operators
- `condition`: Boolean expression to evaluate
- `action`: Content or behavior when condition is true
- `alternative action`: Content or behavior when condition is false

### Mathematical Operators
- `∑(data_set)`: Summation over a collection
- `A ∪ B`: Union of sets A and B
- `A ∩ B`: Intersection of sets A and B

## See Also
- `./claude/npl/instructing/symbolic-logic.md` for advanced logical expressions
- `./claude/npl/syntax/placeholder.md` for variable placeholders
- `./claude/npl/instructing/handlebars.md` for template control structures