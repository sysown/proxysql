# Runtime Flags
Runtime behavior modifiers that alter agent operation and output characteristics at execution time.

## Syntax
`⌜🏳️[...flag definitions...]⌟`

## Purpose
Runtime flags control various aspects of agent behavior, such as verbosity, debugging levels, feature toggles, and output formatting. These flags provide a flexible mechanism to adjust agent operation without changing the underlying code or agent definitions, allowing for dynamic configuration and fine-tuned control.

## Usage
Use runtime flags when you need to:
- Control agent verbosity and output detail levels
- Enable or disable specific features during execution
- Adjust debugging and diagnostic output
- Modify response formatting and structure
- Set operational parameters for specific contexts

## Flag Syntax Patterns
- **Global Flag**: `🏳️flag_name = value`
- **Agent-Specific Flag**: `🏳️@agent_name.flag_name = value`
- **NPL Version Flag**: `🏳️@NPL@version.flag_name = value`
- **Response-Level Flag**: `🏳️@response.flag_name = value`

## Examples

```example
⌜🏳️
🏳️verbose_output = true
🏳️debug_mode = false
🏳️max_response_length = 2000
⌟
```

```example
⌜🏳️
🏳️@data-analyst.show_methodology = true
🏳️@data-analyst.include_charts = false
🏳️@sports-news-agent.historical_context = true
⌟
```

```example
⌜🏳️
🏳️@response.format = structured
🏳️@response.include_metadata = true
🏳️@response.confidence_indicators = true
⌟
```

## Common Flag Categories

### Verbosity Control
- `verbose_output` - Enable detailed explanations and reasoning
- `show_methodology` - Include process and approach descriptions
- `debug_mode` - Show internal processing steps
- `trace_execution` - Log execution path and decision points

### Output Formatting
- `format` - Response structure (structured, conversational, technical)
- `include_metadata` - Add processing information and timestamps
- `confidence_indicators` - Show certainty levels for statements
- `response_length` - Control output verbosity (brief, normal, detailed)

### Feature Toggles
- `enable_examples` - Include illustrative examples in responses
- `historical_context` - Provide background and historical information
- `include_charts` - Generate visual representations when applicable
- `cross_references` - Add related topic links and references

### Processing Control
- `max_response_length` - Limit output size in characters/tokens
- `processing_timeout` - Set maximum execution time
- `retry_attempts` - Number of retry attempts for failed operations
- `cache_responses` - Enable response caching for performance

## Flag Precedence Hierarchy
Runtime flags are applied in order of specificity:
1. **Response-level flags** - Highest precedence, applies to current response
2. **Agent-level flags** - Applies to specific agent instances
3. **NPL-level flags** - Applies to framework version context
4. **Global flags** - Default behavior for all operations

## Flag Data Types
- **Boolean**: `true`, `false`
- **Numeric**: Integer or decimal values
- **String**: Text values (quoted if containing spaces)
- **Enum**: Predefined option sets (e.g., `brief|normal|detailed`)

## Dynamic Flag Modification
Flags can be modified during execution using inline directives:

```example
Initial response with default settings...

⌜🏳️🏳️verbose_output = true⌟

Subsequent responses will include detailed explanations...
```

## See Also
- `.claude/npl/special-section.md` - Overview of special prompt sections
- `.claude/npl/agent.md` - Agent definition syntax and behavior specifications