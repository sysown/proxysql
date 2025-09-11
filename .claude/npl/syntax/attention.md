# Attention Syntax
Critical instruction markers using the 🎯 emoji to mark instructions that require special attention and priority.

## Syntax
`🎯 <important instruction>`

## Purpose
Mark instructions that require the agent's special attention and highest priority processing. Used to stress the importance of critical requirements, security practices, or essential behaviors that must not be overlooked.

## Usage
Use attention markers when:
- Highlighting critical security requirements
- Emphasizing mandatory compliance rules
- Marking essential error handling procedures
- Indicating high-priority constraints or limitations
- Stressing important behavioral requirements

## Examples

```example
🎯 Remember to validate all user inputs before processing.
```
*Emphasizes critical security practice for input validation*

```example
🎯 Never expose sensitive user data in error messages.
```
*Highlights essential privacy protection requirement*

```example
🎯 Always check authentication status before accessing protected resources.
```
*Marks mandatory security verification step*

```example
🎯 Ensure data backup completion before proceeding with migration.
```
*Emphasizes critical operational requirement*

```example
🎯 Handle edge cases gracefully - null values, empty arrays, network timeouts.
```
*Highlights comprehensive error handling requirement*

## Best Practices

### Use Sparingly
- Reserve for truly critical instructions
- Overuse reduces effectiveness and impact
- Focus on security, safety, and essential requirements

### Be Specific
- Clearly state what requires attention
- Provide actionable instructions
- Avoid vague or general statements

### Priority Levels
- Use for highest priority items only
- Combine with other emphasis when appropriate
- Consider alternative emphasis for lower-priority items

## Common Use Cases

### Security Requirements
```example
🎯 Sanitize all SQL queries to prevent injection attacks.
```

### Data Integrity
```example
🎯 Verify data consistency before committing transactions.
```

### User Experience
```example
🎯 Provide clear error messages that guide user resolution.
```

### Performance Constraints
```example
🎯 Limit query results to prevent system overload.
```

### Compliance Requirements
```example
🎯 Log all data access attempts for audit compliance.
```

## Parameters
- `<important instruction>`: The critical requirement or instruction that needs emphasis

## Interaction with Other Syntax
- Can be combined with other syntax elements
- Takes precedence in instruction hierarchies
- Compatible with qualifiers and additional formatting

```example
🎯 Validate user permissions |strict mode, log failures| before data access.
```

## See Also
- `./highlight.md` - Term emphasis syntax using backticks
- `../special-section/secure-prompt.md` - Highest-precedence instruction blocks
- `../directive.md` - Specialized instruction patterns
- `../prefix.md` - Response mode indicators