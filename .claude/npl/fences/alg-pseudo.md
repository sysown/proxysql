# Pseudocode Algorithm Fence
Pseudocode algorithm blocks for high-level algorithmic descriptions using natural language constructs.

## Syntax
```alg-pseudo
<pseudocode specification>
```

## Purpose
Pseudocode algorithm fences provide a natural language approach to algorithm specification, focusing on logical flow and conceptual understanding rather than implementation details. They bridge the gap between problem description and code implementation.

## Usage
Use pseudocode algorithm fences when:
- Describing algorithms at a conceptual level
- Focusing on logic flow rather than syntax
- Creating language-agnostic specifications
- Teaching or explaining algorithmic concepts

## Examples

### Basic Sorting Pseudocode
```example
```alg-pseudo
Algorithm: BubbleSort
Input: Array of n elements
Output: Sorted array

BEGIN
  FOR i = 0 to n-1 DO
    FOR j = 0 to n-i-2 DO
      IF array[j] > array[j+1] THEN
        SWAP array[j] and array[j+1]
      END IF
    END FOR
  END FOR
END
```
```

### Search with Error Handling
```example
```alg-pseudo
Algorithm: SafeLinearSearch
Input: Array A, target value x
Output: Index of x or error message

BEGIN
  IF A is empty THEN
    RETURN "Error: Empty array"
  END IF
  
  FOR each element at index i in A DO
    IF A[i] equals x THEN
      RETURN i
    END IF
  END FOR
  
  RETURN "Element not found"
END
```
```

### Recursive Algorithm
```example
```alg-pseudo
Algorithm: Factorial
Input: Non-negative integer n
Output: n! (factorial of n)

BEGIN
  IF n equals 0 OR n equals 1 THEN
    RETURN 1
  ELSE
    RETURN n * Factorial(n-1)
  END IF
END
```
```

### Data Processing Pipeline
```example
```alg-pseudo
Algorithm: DataProcessor
Input: Raw data stream
Output: Processed results

BEGIN
  WHILE data is available DO
    READ next data chunk
    
    IF data is valid THEN
      CLEAN data (remove nulls, normalize format)
      TRANSFORM data (apply business rules)
      VALIDATE transformed data
      
      IF validation passes THEN
        STORE processed data
        LOG success
      ELSE
        LOG validation error
        MOVE data to error queue
      END IF
    ELSE
      LOG data format error
      SKIP to next chunk
    END IF
  END WHILE
  
  GENERATE processing report
END
```
```

### Conditional Logic with Multiple Paths
```example
```alg-pseudo
Algorithm: GradeCalculator
Input: Student scores array
Output: Letter grade and GPA

BEGIN
  total = 0
  count = 0
  
  FOR each score in scores DO
    IF score is valid (0-100) THEN
      total = total + score
      count = count + 1
    END IF
  END FOR
  
  IF count equals 0 THEN
    RETURN "No valid scores"
  END IF
  
  average = total / count
  
  IF average >= 90 THEN
    grade = "A", gpa = 4.0
  ELSE IF average >= 80 THEN
    grade = "B", gpa = 3.0
  ELSE IF average >= 70 THEN
    grade = "C", gpa = 2.0
  ELSE IF average >= 60 THEN
    grade = "D", gpa = 1.0
  ELSE
    grade = "F", gpa = 0.0
  END IF
  
  RETURN grade, gpa
END
```
```

## Pseudocode Conventions
- `BEGIN` / `END` - Algorithm boundaries
- `IF` / `THEN` / `ELSE` / `END IF` - Conditional statements
- `FOR` / `DO` / `END FOR` - Iteration loops
- `WHILE` / `DO` / `END WHILE` - Conditional loops
- `READ`, `WRITE`, `RETURN` - I/O and flow control
- `SET`, `CALCULATE`, `PROCESS` - Data operations
- Indentation shows logical structure and nesting

## Natural Language Elements
- Use descriptive variable names
- Include validation and error handling
- Explain complex logic with comments
- Focus on what happens, not how it's implemented
- Use domain-specific terminology when appropriate

## See Also
- `./alg.md` - Formal algorithm specification blocks
- `./../../instructing/alg-speak.md` - Algorithm specification language
- `./../../instructing/alg/pseudo.md` - Advanced pseudocode conventions
- `./../../instructing/formal-proof.md` - Formal proof structures