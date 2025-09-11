# JavaScript Algorithm Syntax
JavaScript-specific algorithm specification and implementation patterns within NPL framework.

## Syntax
`alg-javascript` or `alg-js` fence type for JavaScript algorithm implementations

## Purpose
Specify algorithms using modern JavaScript syntax with emphasis on ES6+ features, TypeScript compatibility, and functional programming patterns for web and Node.js environments.

## Usage
Use `alg-javascript` fences when providing JavaScript-specific algorithm implementations, demonstrating modern ES6+ features, or when targeting web/Node.js environments with JavaScript best practices.

## Examples

### Basic Algorithm with Modern Syntax
```alg-javascript
/**
 * Calculate total cost including tax for a list of items
 * @param {Array<{price: number}>} items - Array of item objects with price property
 * @param {number} taxRate - Tax rate as decimal (e.g., 0.08 for 8%)
 * @returns {number} Total cost including tax
 */
function calculateTotal(items, taxRate) {
    const total = items.reduce((sum, item) => sum + item.price, 0);
    const taxAmount = total * taxRate;
    return total + taxAmount;
}

// Arrow function alternative
const calculateTotalArrow = (items, taxRate) => {
    const total = items.reduce((sum, item) => sum + item.price, 0);
    return total + (total * taxRate);
};
```

### Async/Await and Error Handling
```alg-javascript
/**
 * Process user input with validation and async operations
 * @param {string|null} inputData - User input string
 * @returns {Promise<string>} Processed result or error message
 * @throws {Error} When input format is invalid
 */
async function processUserInput(inputData) {
    if (!inputData) {
        return "Empty input error";
    }
    
    if (!isValidInput(inputData)) {
        throw new Error("Invalid input format");
    }
    
    try {
        const result = await processInputAsync(inputData);
        return `Success: ${result}`;
    } catch (error) {
        return `Processing error: ${error.message}`;
    }
}

const isValidInput = (data) => data?.trim()?.length > 0;

const processInputAsync = async (data) => {
    // Simulate async operation
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            if (data.includes('error')) {
                reject(new Error('Simulated processing error'));
            } else {
                resolve(`Processed: ${data.toUpperCase()}`);
            }
        }, 100);
    });
};
```

### Array and Object Manipulation
```alg-javascript
/**
 * Find maximum value in array using modern methods
 * @param {number[]} array - Array of numeric values
 * @returns {number} Maximum value in array
 * @throws {Error} When array is empty
 */
const findMaxValue = (array) => {
    if (!Array.isArray(array) || array.length === 0) {
        throw new Error("Cannot find max of empty array");
    }
    
    return Math.max(...array);
};

/**
 * Generate Fibonacci sequence using generator function
 * @param {number} n - Number of Fibonacci terms to generate
 * @yields {number} Next Fibonacci number in sequence
 */
function* fibonacciGenerator(n) {
    let [a, b] = [0, 1];
    for (let i = 0; i < n; i++) {
        yield a;
        [a, b] = [b, a + b];
    }
}

// Usage with destructuring and spread
const firstTenFib = [...fibonacciGenerator(10)];
```

### Object-Oriented Algorithms
```alg-javascript
/**
 * Graph algorithms implementation using ES6 classes
 */
class GraphAlgorithms {
    /**
     * Breadth-first search pathfinding
     * @param {Object} graph - Adjacency list representation
     * @param {*} start - Starting node
     * @param {*} target - Target node
     * @returns {Array|null} Path from start to target, or null if no path exists
     */
    static breadthFirstSearch(graph, start, target) {
        if (start === target) return [start];
        
        const queue = [[start, [start]]];
        const visited = new Set([start]);
        
        while (queue.length > 0) {
            const [current, path] = queue.shift();
            
            for (const neighbor of (graph[current] || [])) {
                if (neighbor === target) {
                    return [...path, neighbor];
                }
                
                if (!visited.has(neighbor)) {
                    visited.add(neighbor);
                    queue.push([neighbor, [...path, neighbor]]);
                }
            }
        }
        
        return null;
    }
    
    /**
     * Dijkstra's shortest path algorithm
     * @param {Object} graph - Weighted adjacency list
     * @param {*} start - Starting node
     * @returns {Object} Object mapping nodes to shortest distances
     */
    static dijkstraShortestPath(graph, start) {
        const distances = new Map();
        const heap = [[0, start]];
        const visited = new Set();
        
        // Initialize distances
        Object.keys(graph).forEach(node => {
            distances.set(node, node === start ? 0 : Infinity);
        });
        
        while (heap.length > 0) {
            heap.sort((a, b) => a[0] - b[0]); // Simple heap simulation
            const [currentDist, current] = heap.shift();
            
            if (visited.has(current)) continue;
            visited.add(current);
            
            for (const [neighbor, weight] of Object.entries(graph[current] || {})) {
                const distance = currentDist + weight;
                
                if (distance < distances.get(neighbor)) {
                    distances.set(neighbor, distance);
                    heap.push([distance, neighbor]);
                }
            }
        }
        
        return Object.fromEntries(distances);
    }
}
```

### Functional Programming Patterns
```alg-javascript
/**
 * Merge sort implementation using functional approach
 * @param {number[]} arr - Array of numbers to sort
 * @returns {number[]} Sorted array
 */
const mergeSort = (arr) => {
    if (arr.length <= 1) return arr;
    
    const mid = Math.floor(arr.length / 2);
    const left = mergeSort(arr.slice(0, mid));
    const right = mergeSort(arr.slice(mid));
    
    return merge(left, right);
};

const merge = (left, right) => {
    const result = [];
    let [i, j] = [0, 0];
    
    while (i < left.length && j < right.length) {
        if (left[i] <= right[j]) {
            result.push(left[i++]);
        } else {
            result.push(right[j++]);
        }
    }
    
    return [...result, ...left.slice(i), ...right.slice(j)];
};

// Pipeline pattern for data processing
const processData = (data) => 
    data
        .filter(item => item.active)
        .map(item => ({ ...item, processed: true }))
        .sort((a, b) => a.priority - b.priority)
        .reduce((acc, item) => ({ ...acc, [item.id]: item }), {});
```

### TypeScript-Compatible Patterns
```alg-javascript
/**
 * Type-aware algorithm implementation (JavaScript with JSDoc for TypeScript compatibility)
 * @template T
 * @param {T[]} items - Array of items to process
 * @param {(item: T) => boolean} predicate - Filtering predicate
 * @param {(item: T) => any} transform - Transformation function
 * @returns {any[]} Processed items
 */
const processItems = (items, predicate, transform) => {
    return items
        .filter(predicate)
        .map(transform);
};

/**
 * Generic comparison function
 * @template T
 * @param {T} a - First item
 * @param {T} b - Second item
 * @param {keyof T} key - Property to compare
 * @returns {number} Comparison result
 */
const compareBy = (a, b, key) => {
    if (a[key] < b[key]) return -1;
    if (a[key] > b[key]) return 1;
    return 0;
};
```

## JavaScript-Specific Conventions

### Modern ES6+ Features
- Use `const`/`let` instead of `var`
- Prefer arrow functions for simple operations
- Use template literals for string interpolation
- Leverage destructuring assignment
- Use spread operator for array/object operations

### Async Operations
- Use `async/await` for Promise handling
- Implement proper error handling with try-catch
- Use Promise.all() for concurrent operations
- Consider Promise.race() for timeout scenarios

### Functional Programming
- Prefer immutable operations
- Use array methods (map, filter, reduce)
- Implement pure functions when possible
- Use function composition for complex transformations

### Performance Considerations
- Use Set/Map for O(1) lookups
- Consider typed arrays for numeric operations
- Implement lazy evaluation with generators
- Use requestAnimationFrame for UI-heavy algorithms

## Parameters
- **JSDoc Comments**: Required for function documentation
- **Error Handling**: Include try-catch for async operations
- **Type Safety**: Use JSDoc types or TypeScript patterns
- **Browser/Node Compatibility**: Consider target environment

## See Also
- `./pseudo.md` for language-agnostic algorithm specifications
- `./flowchart.md` for visual algorithm representations
- `./python.md` for Python algorithm implementations
- `../annotation.md` for code annotation patterns