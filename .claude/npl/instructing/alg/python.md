# Python Algorithm Syntax
Python-specific algorithm specification and implementation patterns within NPL framework.

## Syntax
`alg-python` fence type for Python algorithm implementations

## Purpose
Specify algorithms using Python syntax with emphasis on clarity, type hints, and modern Python conventions for algorithm documentation and implementation guidance.

## Usage
Use `alg-python` fences when providing Python-specific algorithm implementations, when type safety is important, or when demonstrating Python best practices for algorithmic solutions.

## Examples

### Basic Algorithm with Type Hints
```alg-python
def calculate_total(items: list[dict], tax_rate: float) -> float:
    """Calculate total cost including tax for a list of items.
    
    Args:
        items: List of item dictionaries with 'price' keys
        tax_rate: Tax rate as decimal (e.g., 0.08 for 8%)
        
    Returns:
        Total cost including tax
    """
    total = sum(item['price'] for item in items)
    tax_amount = total * tax_rate
    return total + tax_amount
```

### Control Flow and Error Handling
```alg-python
def process_user_input(input_data: str | None) -> str:
    """Process user input with validation and error handling.
    
    Args:
        input_data: User input string or None
        
    Returns:
        Processed result or error message
        
    Raises:
        ValueError: When input format is invalid
    """
    if not input_data:
        return "Empty input error"
    
    if not is_valid_input(input_data):
        raise ValueError("Invalid input format")
    
    try:
        result = process_input(input_data)
        return f"Success: {result}"
    except Exception as e:
        return f"Processing error: {e}"

def is_valid_input(data: str) -> bool:
    """Validate input data format."""
    return data.strip() and len(data) > 0
```

### Iterative Algorithms
```alg-python
from typing import Iterator

def find_max_value(array: list[int | float]) -> int | float:
    """Find maximum value in array using iterative approach.
    
    Args:
        array: List of numeric values
        
    Returns:
        Maximum value in array
        
    Raises:
        ValueError: When array is empty
    """
    if not array:
        raise ValueError("Cannot find max of empty array")
    
    max_val = array[0]
    for value in array[1:]:
        if value > max_val:
            max_val = value
    
    return max_val

def fibonacci_generator(n: int) -> Iterator[int]:
    """Generate Fibonacci sequence up to n terms.
    
    Args:
        n: Number of Fibonacci terms to generate
        
    Yields:
        Next Fibonacci number in sequence
    """
    a, b = 0, 1
    for _ in range(n):
        yield a
        a, b = b, a + b
```

### Data Structure Algorithms
```alg-python
from collections import defaultdict
from typing import Any, Dict, List, Set

class GraphAlgorithms:
    """Collection of graph algorithms."""
    
    @staticmethod
    def breadth_first_search(
        graph: Dict[Any, List[Any]], 
        start: Any, 
        target: Any
    ) -> List[Any] | None:
        """BFS pathfinding algorithm.
        
        Args:
            graph: Adjacency list representation
            start: Starting node
            target: Target node
            
        Returns:
            Path from start to target, or None if no path exists
        """
        from collections import deque
        
        if start == target:
            return [start]
        
        queue = deque([(start, [start])])
        visited: Set[Any] = {start}
        
        while queue:
            current, path = queue.popleft()
            
            for neighbor in graph.get(current, []):
                if neighbor == target:
                    return path + [neighbor]
                
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        
        return None
    
    @staticmethod
    def dijkstra_shortest_path(
        graph: Dict[Any, Dict[Any, int]], 
        start: Any
    ) -> Dict[Any, int]:
        """Dijkstra's shortest path algorithm.
        
        Args:
            graph: Weighted adjacency list
            start: Starting node
            
        Returns:
            Dictionary mapping nodes to shortest distances
        """
        import heapq
        
        distances = defaultdict(lambda: float('inf'))
        distances[start] = 0
        heap = [(0, start)]
        visited: Set[Any] = set()
        
        while heap:
            current_dist, current = heapq.heappop(heap)
            
            if current in visited:
                continue
                
            visited.add(current)
            
            for neighbor, weight in graph.get(current, {}).items():
                distance = current_dist + weight
                
                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    heapq.heappush(heap, (distance, neighbor))
        
        return dict(distances)
```

### Recursive Algorithms
```alg-python
def merge_sort(arr: list[int]) -> list[int]:
    """Merge sort implementation with divide-and-conquer.
    
    Args:
        arr: List of integers to sort
        
    Returns:
        Sorted list
    """
    if len(arr) <= 1:
        return arr
    
    mid = len(arr) // 2
    left = merge_sort(arr[:mid])
    right = merge_sort(arr[mid:])
    
    return merge(left, right)

def merge(left: list[int], right: list[int]) -> list[int]:
    """Merge two sorted lists."""
    result = []
    i = j = 0
    
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1
    
    result.extend(left[i:])
    result.extend(right[j:])
    return result
```

## Python-Specific Conventions

### Type Annotations
- Use modern type hints: `list[int]`, `dict[str, Any]`
- Specify return types and parameter types
- Use `| None` for optional returns
- Import from `typing` for complex types

### Documentation
- Use docstrings with Google or NumPy style
- Include `Args:`, `Returns:`, `Raises:` sections
- Provide usage examples when helpful

### Error Handling
- Use specific exception types
- Provide meaningful error messages
- Handle edge cases explicitly

### Code Style
- Follow PEP 8 conventions
- Use descriptive variable names
- Prefer comprehensions for simple operations
- Use appropriate data structures (defaultdict, deque, etc.)

## Parameters
- **Type Hints**: Specify input/output types for clarity
- **Docstrings**: Required for algorithm documentation
- **Error Handling**: Include appropriate exception handling
- **Performance**: Consider time/space complexity implications

## See Also
- `./pseudo.md` for language-agnostic algorithm specifications
- `./flowchart.md` for visual algorithm representations
- `./javascript.md` for JavaScript algorithm implementations
- `../annotation.md` for code annotation patterns