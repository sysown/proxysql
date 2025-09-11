# In-Fill Size Indicators
Size qualifiers for content generation areas that specify the expected length or volume of generated content.

## Syntax
`[...<size>]` or `[...<count><size>]` or `[...<range><size>]`

## Purpose
Control the amount of content generated in fill-in areas by specifying units and quantities.

## Usage
Add size indicators to in-fill areas to guide content generation length and scope. Use when precise content volume requirements are needed.

## Size Indicators

### Basic Units
- `p` - paragraphs
- `pg` - pages  
- `l` - lines
- `s` - sentences
- `w` - words
- `i` - items
- `r` - rows
- `t` - tokens

### Count Formats
- **Simple count**: `[...3w]` - exactly 3 words
- **Range**: `[...3-5w]` - between 3 and 5 words
- **Minimum**: `[...3+w]` - 3 or more words
- **Maximum**: `[...3-w]` - up to 3 words
- **Complex range**: `[...3-9+r]` - 3 to 9 or more rows

## Examples

```example
Write a product description [...2-3p] for the new smartphone.
```
*Generates 2-3 paragraphs of product description content*

```example
Create a shopping list [...5-10i] for the dinner party.
```
*Generates a list with 5-10 items*

```example
Summarize the findings [...1-2s] for each section.
```
*Generates 1-2 sentences per section*

```example
Provide code examples [...10-20l] showing the implementation.
```
*Generates code examples spanning 10-20 lines*

## Parameters
- `count`: Specific number (e.g., `3`, `5`)
- `range`: Range with dash (e.g., `3-5`, `1-10`)
- `minimum`: Number with plus (e.g., `3+`)
- `maximum`: Number with dash (e.g., `3-`)
- `size`: Unit indicator (`p`, `pg`, `l`, `s`, `w`, `i`, `r`, `t`)

## See Also
- `./fill-in.md` - Basic in-fill syntax
- `./qualifier.md` - Additional qualifications for in-fill areas
- `../directive.md` - Specialized instruction patterns