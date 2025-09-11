# Pseudocode Conventions
Standardized pseudocode formatting and conventions for algorithm specification in NPL framework.

## Syntax
`alg-pseudo` fence type for pseudocode algorithm blocks

## Purpose
Define algorithms using structured, language-agnostic pseudocode that clearly communicates logic flow and operations without implementation-specific syntax constraints.

## Usage
Use `alg-pseudo` fences when specifying algorithms that need to be understandable across different programming contexts or when the focus should be on logic rather than syntax.

## Examples

### Basic Algorithm Structure
```alg-pseudo
ALGORITHM calculateTotal(items, taxRate)
BEGIN
    total ← 0
    FOR each item IN items DO
        total ← total + item.price
    END FOR
    
    taxAmount ← total × taxRate
    finalTotal ← total + taxAmount
    
    RETURN finalTotal
END
```

### Control Flow Structures
```alg-pseudo
ALGORITHM processUserInput(input)
BEGIN
    IF input IS NOT empty THEN
        IF input IS valid THEN
            result ← processInput(input)
            RETURN result
        ELSE
            RETURN "Invalid input error"
        END IF
    ELSE
        RETURN "Empty input error"
    END IF
END
```

### Loop Constructs
```alg-pseudo
ALGORITHM findMaxValue(array)
BEGIN
    max ← array[0]
    index ← 1
    
    WHILE index < length(array) DO
        IF array[index] > max THEN
            max ← array[index]
        END IF
        index ← index + 1
    END WHILE
    
    RETURN max
END
```

## Conventions

### Variable Assignment
- Use `←` for assignment operations
- Use `=` for equality comparisons
- Use `:=` for initialization when needed

### Control Structures
- **Conditionals**: `IF...THEN...ELSE...END IF`
- **Loops**: `FOR...DO...END FOR`, `WHILE...DO...END WHILE`, `REPEAT...UNTIL`
- **Functions**: `ALGORITHM name(parameters)...BEGIN...END`

### Operations
- Mathematical: `+`, `-`, `×`, `÷`, `MOD`
- Logical: `AND`, `OR`, `NOT`
- Comparison: `=`, `≠`, `<`, `>`, `≤`, `≥`

### Data Structures
- Arrays: `array[index]`, `length(array)`
- Objects: `object.property`
- Collections: `add(item)`, `remove(item)`, `contains(item)`

## Parameters
- **BEGIN/END**: Algorithm block boundaries
- **INPUT/OUTPUT**: Explicit parameter and return specifications
- **PRECONDITION/POSTCONDITION**: Algorithm constraints and guarantees

## See Also
- `./alg/flowchart.md` for visual algorithm representations
- `./alg/python.md` for Python-specific algorithm syntax
- `./alg/javascript.md` for JavaScript-specific algorithm syntax
- `../second-order.md` for higher-order algorithmic patterns