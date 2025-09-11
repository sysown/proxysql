# Algorithm Specification Language
Structured notation for defining algorithms, computational processes, and procedural logic through specialized fence blocks.

## Syntax
```syntax
```alg
[algorithm specification]
```

```alg-pseudo
[pseudocode implementation]
```

```alg-<language>
[language-specific algorithm]
```
```

## Purpose
Algorithm specification language provides formal notation for expressing computational logic, step-by-step procedures, and algorithmic thinking patterns in structured, readable formats.

## Usage
Use alg-speak when you need to:
- Define precise computational procedures
- Specify algorithm implementations in pseudocode
- Document complex logic flows
- Provide language-specific algorithm variants

## Algorithm Fence Types

### General Algorithm (`alg`)
```example
```alg
Algorithm: FindMaximum(array A)
1. max ← A[0]
2. for i = 1 to length(A) - 1 do
3.   if A[i] > max then
4.     max ← A[i]
5.   end if
6. end for
7. return max
```
```

### Pseudocode Algorithm (`alg-pseudo`)
```example
```alg-pseudo
PROCEDURE BinarySearch(array, target):
  left = 0
  right = array.length - 1
  
  WHILE left <= right:
    mid = (left + right) / 2
    IF array[mid] = target:
      RETURN mid
    ELSE IF array[mid] < target:
      left = mid + 1
    ELSE:
      right = mid - 1
    END IF
  END WHILE
  
  RETURN -1
```
```

### Language-Specific Algorithms
```example
```alg-python
def quicksort(arr):
    if len(arr) <= 1:
        return arr
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    return quicksort(left) + middle + quicksort(right)
```
```

## Notation Conventions

### Assignment and Operations
- Assignment: `variable ← value` or `variable = value`
- Comparison: `=`, `≠`, `<`, `>`, `≤`, `≥`
- Logic: `AND`, `OR`, `NOT`
- Mathematics: `+`, `-`, `×`, `÷`, `mod`

### Control Structures
- Conditionals: `IF...THEN...ELSE...END IF`
- Loops: `FOR...TO...DO...END FOR`, `WHILE...DO...END WHILE`
- Procedures: `PROCEDURE name(parameters)...END PROCEDURE`

### Mathematical Notation
- Summation: `∑(expression)`
- Set operations: `A ∪ B`, `A ∩ B`
- Logic operators: `∀`, `∃`, `⟹`, `⟺`

## Advanced Patterns

### Recursive Algorithms
```example
```alg
Algorithm: Fibonacci(n)
1. if n ≤ 1 then
2.   return n
3. else
4.   return Fibonacci(n-1) + Fibonacci(n-2)
5. end if
```
```

### Data Structure Operations
```example
```alg-pseudo
PROCEDURE TreeTraversal(node):
  IF node ≠ null:
    PRINT node.value
    TreeTraversal(node.left)
    TreeTraversal(node.right)
  END IF
```
```

## Complexity Analysis
Include time and space complexity when relevant:
```example
```alg
Algorithm: LinearSearch(array A, target x)
// Time Complexity: O(n)
// Space Complexity: O(1)
1. for i = 0 to length(A) - 1 do
2.   if A[i] = x then
3.     return i
4.   end if
5. end for
6. return -1
```
```

## See Also
- `./.claude/npl/fences/alg.md` - Algorithm fence block specifications
- `./.claude/npl/fences/alg-pseudo.md` - Pseudocode formatting conventions
- `./.claude/npl/instructing/symbolic-logic.md` - Symbolic logic representations
- `./.claude/npl/syntax/logic-operators.md` - Mathematical and logical operators