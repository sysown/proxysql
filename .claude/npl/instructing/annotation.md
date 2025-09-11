# Iterative Refinement Patterns
Annotation-based techniques for progressive improvement of code, designs, and solutions through structured feedback and modification cycles.

## Syntax
```syntax
```annotation
original: [existing content]
issues: [identified problems]
refinement: [improved version]
```

```annotation-cycle
iteration: <number>
focus: <area of improvement>
changes: [specific modifications]
validation: [verification method]
```
```

## Purpose
Annotation patterns enable systematic improvement of outputs through iterative cycles, allowing for progressive refinement based on feedback, testing, and evolving requirements.

## Usage
Use annotation patterns for:
- Code review and improvement cycles
- UX design iteration processes
- Progressive solution refinement
- Quality assurance workflows

## Annotation Types

### Basic Refinement
```example
```annotation
original: |
  function calculate(a, b) {
    return a + b;
  }
issues:
  - No input validation
  - Limited to addition only
refinement: |
  function calculate(a, b, operation = 'add') {
    if (typeof a !== 'number' || typeof b !== 'number') {
      throw new Error('Invalid input: numbers required');
    }
    switch(operation) {
      case 'add': return a + b;
      case 'subtract': return a - b;
      case 'multiply': return a * b;
      case 'divide': return b !== 0 ? a / b : null;
      default: throw new Error('Unsupported operation');
    }
  }
```
```

### Progressive Design Iteration
```example
```annotation-cycle
iteration: 1
focus: User interface layout
changes:
  - Moved navigation to sidebar
  - Increased button sizes for mobile
  - Added color contrast improvements
validation: Accessibility audit + user testing
```
```

### Multi-Stage Refinement
```example
```annotation
stage: analysis
findings:
  - Performance bottleneck in data processing
  - Memory usage could be optimized
  - Error handling needs improvement

stage: implementation
changes:
  - Implemented data streaming instead of batch loading
  - Added memory pool for object reuse
  - Enhanced error recovery mechanisms

stage: validation
metrics:
  - 40% performance improvement
  - 25% reduction in memory usage
  - Zero unhandled exceptions in testing
```
```

## Refinement Patterns

### Code Enhancement Cycle
1. **Identify**: Mark areas needing improvement
2. **Analyze**: Document specific issues or limitations
3. **Refine**: Implement enhanced version
4. **Validate**: Test and verify improvements
5. **Iterate**: Repeat cycle if further refinement needed

### Design Evolution Pattern
```example
```annotation
version: 1.0
design: Initial wireframe with basic functionality
feedback: Users find navigation confusing

version: 2.0  
design: Reorganized navigation with clear hierarchy
feedback: Better, but mobile experience needs work

version: 3.0
design: Responsive design with mobile-first approach
feedback: Excellent usability across devices
```
```

### Quality Improvement Framework
```example
```annotation-cycle
cycle: security-review
focus: Input validation and sanitization
issues:
  - SQL injection vulnerabilities
  - Cross-site scripting risks
  - Insufficient authorization checks
remediation:
  - Parameterized queries implemented
  - Input sanitization added
  - Role-based access control enhanced
verification: Penetration testing passed
```
```

## Advanced Techniques

### Collaborative Refinement
```example
```annotation
author: developer-a
original: [initial implementation]
reviewer: developer-b
suggestions: [code review feedback]
author: developer-a
refinement: [updated implementation]
reviewer: developer-b
approval: Changes address all concerns
```
```

### Metric-Driven Improvement
```example
```annotation
baseline_metrics:
  - Load time: 3.2s
  - Error rate: 2.1%
  - User satisfaction: 3.2/5
target_improvements:
  - Load time: <2.0s
  - Error rate: <1.0%
  - User satisfaction: >4.0/5
implementation: [optimization strategies]
results:
  - Load time: 1.8s ✓
  - Error rate: 0.7% ✓ 
  - User satisfaction: 4.3/5 ✓
```
```

## Integration with Other Patterns

### With Chain of Thought
Use annotation to refine reasoning processes:
```example
```annotation
thought_process: [initial reasoning]
reflection: [identified logical gaps]
refined_reasoning: [improved analysis]
conclusion: [updated solution]
```
```

### With Template Systems
Apply refinement to template designs:
```example
```annotation
template_version: 1
issues: [layout problems]
template_version: 2  
improvements: [enhanced structure]
```
```

## See Also
- `./.claude/npl/pumps/npl-reflection.md` - Self-assessment patterns
- `./.claude/npl/pumps/npl-critique.md` - Critical analysis techniques
- `./.claude/npl/instructing/second-order.md` - Higher-order improvement patterns