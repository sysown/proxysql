# Symbolic Logic Representations
Formal symbolic notation systems for expressing logical relationships, mathematical operations, and reasoning structures using standardized mathematical symbols.

## Syntax
```syntax
∀x P(x) - Universal quantification
∃x P(x) - Existential quantification  
P(x) → Q(x) - Logical implication
P(x) ↔ Q(x) - Logical equivalence
```

## Purpose
Symbolic logic provides precise, unambiguous notation for expressing logical relationships, mathematical concepts, and reasoning patterns that can be manipulated and analyzed systematically.

## Usage
Use symbolic logic for:
- Formal specification of logical relationships  
- Mathematical proof construction
- Precise expression of conditional logic
- Set theory and mathematical operations
- Algorithmic reasoning patterns

## Core Symbols

### Logical Connectives
```example
∧ - Logical AND (conjunction)
∨ - Logical OR (disjunction)  
¬ - Logical NOT (negation)
→ - Implication (if...then)
↔ - Biconditional (if and only if)
⊕ - Exclusive OR (XOR)
```

### Quantifiers
```example
∀ - Universal quantifier ("for all")
∃ - Existential quantifier ("there exists")
∃! - Unique existence ("there exists exactly one")
∄ - Non-existence ("there does not exist")
```

### Set Operations  
```example
∪ - Union
∩ - Intersection
∖ - Set difference
⊆ - Subset
⊂ - Proper subset
∈ - Element of
∉ - Not element of
∅ - Empty set
```

### Mathematical Relations
```example
= - Equality
≠ - Inequality  
< - Less than
≤ - Less than or equal
> - Greater than
≥ - Greater than or equal
≡ - Equivalence
≈ - Approximately equal
```

## Application Patterns

### Propositional Logic
```example
```symbolic
Given propositions P, Q, R:
- Modus Ponens: (P → Q) ∧ P ⊢ Q
- Modus Tollens: (P → Q) ∧ ¬Q ⊢ ¬P
- Hypothetical Syllogism: (P → Q) ∧ (Q → R) ⊢ (P → R)
- Disjunctive Syllogism: (P ∨ Q) ∧ ¬P ⊢ Q
```
```

### Predicate Logic
```example
```symbolic
Domain: Natural numbers ℕ
Predicates:
- Even(x) ≔ ∃k ∈ ℕ(x = 2k)
- Prime(x) ≔ x > 1 ∧ ∀y((y|x) → (y = 1 ∨ y = x))

Statements:
- ∀x ∈ ℕ(Even(x) ∨ Odd(x))
- ∃x ∈ ℕ(Prime(x) ∧ Even(x)) // True: x = 2
- ∀x ∈ ℕ(Prime(x) ∧ x > 2 → Odd(x))
```
```

### Set Theory Applications
```example
```symbolic
Set Relationships:
- Subset: A ⊆ B ↔ ∀x(x ∈ A → x ∈ B)
- Equal sets: A = B ↔ (A ⊆ B ∧ B ⊆ A)
- Disjoint: A ∩ B = ∅
- Complement: A^c = {x : x ∉ A}

Set Operations:
- Union: A ∪ B = {x : x ∈ A ∨ x ∈ B}
- Intersection: A ∩ B = {x : x ∈ A ∧ x ∈ B}
- Difference: A ∖ B = {x : x ∈ A ∧ x ∉ B}
```
```

## Advanced Symbolic Patterns

### Function Notation
```example
```symbolic
Function Definition:
f: A → B (f maps A to B)
f(x) = y where x ∈ A, y ∈ B

Function Properties:
- Injective: ∀x₁,x₂ ∈ A(f(x₁) = f(x₂) → x₁ = x₂)
- Surjective: ∀y ∈ B∃x ∈ A(f(x) = y)  
- Bijective: Injective ∧ Surjective
```
```

### Algorithmic Logic
```example
```symbolic
Conditional Logic in Algorithms:
if (condition) { action } else { alternative }
≡ (condition → action) ∧ (¬condition → alternative)

Loop Invariants:
∀i(0 ≤ i ≤ n → Invariant(i))
where Invariant(i) specifies what remains true during iteration
```
```

### Mathematical Proofs
```example
```symbolic
Proof by Contradiction:
To prove P, assume ¬P and derive contradiction:
¬P ⊢ (Q ∧ ¬Q) ⊢ ⊥
Therefore: ⊢ P

Proof by Induction:
Base case: P(0)
Inductive step: ∀k(P(k) → P(k+1))
Conclusion: ∀n ∈ ℕ(P(n))
```
```

## Complex Expressions

### Modal Logic
```example
```symbolic
Necessity and Possibility:
□P - "P is necessarily true"
◇P - "P is possibly true"
□P → P - "What is necessary is true"
P → ◇P - "What is true is possible"
□(P → Q) → (□P → □Q) - Kripke's K axiom
```
```

### Temporal Logic
```example
```symbolic
Temporal Operators:
◯P - "P holds in the next state"
□P - "P always holds" (globally)
◇P - "P eventually holds" (finally)
P U Q - "P holds until Q holds"

Properties:
◇□P - "P eventually always holds"
□◇P - "P holds infinitely often"
```
```

## Integration with Other Systems

### With Algorithm Specification
```example
```symbolic
Algorithm Correctness:
{Precondition} Algorithm {Postcondition}
∀x(Precondition(x) → Postcondition(Algorithm(x)))

Complexity Analysis:
∃c,n₀∀n≥n₀(T(n) ≤ c·f(n))
// Algorithm runtime T(n) is O(f(n))
```
```

### With Formal Proofs
```example
```symbolic
Proof Structure:
Premises: P₁, P₂, ..., Pₙ
Inference Rules: R₁, R₂, ..., Rₘ  
Conclusion: Q

Validity: (P₁ ∧ P₂ ∧ ... ∧ Pₙ) → Q
```
```

## Practical Applications

### Specification Languages
Use symbolic logic to specify:
- System requirements and constraints
- API contracts and interfaces  
- Database integrity constraints
- Security policies and access controls

### Automated Reasoning
Enable automated systems to:
- Verify logical consistency
- Generate proofs automatically
- Check satisfiability of constraints
- Optimize logical expressions

## Common Patterns in NPL Context

### Conditional Content Generation
```example
if (user.role == 'administrator') { Show admin panel } else { Show user dashboard }
≡ (Administrator(user) → AdminPanel) ∧ (¬Administrator(user) → UserDashboard)
```

### Set-Based Operations
```example
Customer segmentation:
sports_enthusiasts ∩ health_focused
≡ {x : SportsInterest(x) ∧ HealthFocus(x)}
```

## See Also
- `./.claude/npl/instructing/formal-proof.md` - Formal proof construction
- `./.claude/npl/instructing/second-order.md` - Higher-order logic patterns
- `./.claude/npl/syntax/logic-operators.md` - Mathematical reasoning operators
- `./.claude/npl/instructing/alg-speak.md` - Algorithm specification language