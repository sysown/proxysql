# Algorithm Fence
Algorithm specification blocks for defining computational procedures and problem-solving approaches.

## Syntax
```alg
<algorithm specification>
```

## Purpose
Algorithm fences provide a structured way to specify computational procedures, problem-solving approaches, and step-by-step processes. They support both high-level algorithmic descriptions and detailed implementation guidance.

## Usage
Use algorithm fences when defining:
- Computational procedures and logic flows
- Problem-solving methodologies
- Step-by-step process specifications
- Implementation strategies and approaches

## Examples

### Sorting Algorithm
```example
```alg
name: quicksort
input: array A of comparable elements
output: sorted array A

procedure quicksort(A, low, high):
  if low < high:
    pivot_index = partition(A, low, high)
    quicksort(A, low, pivot_index - 1)
    quicksort(A, pivot_index + 1, high)

procedure partition(A, low, high):
  pivot = A[high]
  i = low - 1
  for j = low to high - 1:
    if A[j] <= pivot:
      i = i + 1
      swap A[i] with A[j]
  swap A[i + 1] with A[high]
  return i + 1
```
```

### Search Algorithm
```example
```alg
name: binary_search
input: sorted array A, target value x
output: index of x in A, or -1 if not found

procedure binary_search(A, x):
  left = 0
  right = length(A) - 1
  
  while left <= right:
    mid = (left + right) / 2
    if A[mid] == x:
      return mid
    else if A[mid] < x:
      left = mid + 1
    else:
      right = mid - 1
  
  return -1
```
```

### Graph Algorithm
```example
```alg
name: dijkstra
input: weighted graph G, source vertex s
output: shortest distances from s to all vertices

procedure dijkstra(G, s):
  for each vertex v in G:
    dist[v] = infinity
    prev[v] = undefined
  
  dist[s] = 0
  Q = all vertices in G
  
  while Q is not empty:
    u = vertex in Q with minimum dist[u]
    remove u from Q
    
    for each neighbor v of u:
      alt = dist[u] + weight(u, v)
      if alt < dist[v]:
        dist[v] = alt
        prev[v] = u
  
  return dist, prev
```
```

### Optimization Algorithm
```example
```alg
name: gradient_descent
input: function f, initial point x₀, learning rate α
output: optimized point x*

procedure gradient_descent(f, x₀, α):
  x = x₀
  tolerance = 1e-6
  max_iterations = 1000
  
  for i = 1 to max_iterations:
    gradient = ∇f(x)
    if ||gradient|| < tolerance:
      break
    x = x - α * gradient
  
  return x
```
```

## Algorithm Components
- `name`: Algorithm identifier
- `input`: Required input parameters and constraints
- `output`: Expected output format and guarantees
- `procedure`: Step-by-step algorithmic process
- `complexity`: Time and space complexity analysis (optional)
- `invariants`: Loop invariants and preconditions (optional)

## Mathematical Notation
Algorithms support standard mathematical notation:
- `∇f(x)` - Gradient notation
- `||x||` - Norm notation
- `∑`, `∏` - Summation and product operators
- `∈`, `∉` - Set membership
- `≤`, `≥`, `≠` - Comparison operators
- `∞` - Infinity symbol

## See Also
- `./alg-pseudo.md` - Pseudocode algorithm blocks
- `./../../instructing/alg-speak.md` - Algorithm specification language
- `./../../instructing/alg/python.md` - Python algorithm implementations
- `./../../instructing/symbolic-logic.md` - Symbolic logic representations