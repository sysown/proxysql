# Formal Proof Structures
Structured frameworks for constructing rigorous mathematical and logical proofs using systematic reasoning methods and formal inference rules.

## Syntax
```syntax
```proof
Given: [premises]
To Prove: [conclusion]
Proof:
  1. [step] - [justification]
  2. [step] - [justification]
  ...
  n. [conclusion] - [final justification]
```

```natural-deduction
[premises]
─────────── [rule name]
[conclusion]
```
```

## Purpose
Formal proof structures provide systematic frameworks for constructing valid logical arguments, ensuring mathematical rigor, and establishing the truth of statements through step-by-step reasoning.

## Usage
Use formal proofs for:
- Mathematical theorem verification
- Logical argument validation  
- Algorithm correctness proofs
- System property verification
- Scientific hypothesis testing

## Proof Methods

### Direct Proof
```example
```proof
Theorem: If n is even, then n² is even.
Given: n is even (n = 2k for some integer k)
To Prove: n² is even

Proof:
1. n = 2k - Given (n is even)
2. n² = (2k)² - Substitution
3. n² = 4k² - Algebraic manipulation  
4. n² = 2(2k²) - Factoring
5. Since 2k² is an integer, n² = 2m where m = 2k² - Definition
6. Therefore, n² is even - Definition of even number ∎
```
```

### Proof by Contradiction
```example
```proof
Theorem: √2 is irrational
Given: √2 exists as a real number
To Prove: √2 cannot be expressed as p/q where p,q are integers with gcd(p,q) = 1

Proof by Contradiction:
1. Assume √2 is rational - Assumption for contradiction
2. Then √2 = p/q where gcd(p,q) = 1 - Definition of rational
3. 2 = p²/q² - Squaring both sides
4. 2q² = p² - Algebraic manipulation
5. p² is even - Since 2q² = p²
6. p is even - If p² even, then p even
7. p = 2r for some integer r - Definition of even
8. 2q² = (2r)² = 4r² - Substitution
9. q² = 2r² - Dividing by 2
10. q² is even, therefore q is even - Same logic as steps 5-6
11. Both p and q are even - From steps 6 and 10
12. gcd(p,q) ≥ 2 - Contradiction with assumption gcd(p,q) = 1
13. Therefore, √2 is irrational ∎
```
```

### Mathematical Induction
```example
```proof
Theorem: For all n ≥ 1, 1 + 2 + 3 + ... + n = n(n+1)/2
To Prove: ∀n ∈ ℕ₊, ∑ᵢ₌₁ⁿ i = n(n+1)/2

Proof by Induction:
Base Case (n = 1):
1. LHS = 1 - Direct calculation
2. RHS = 1(1+1)/2 = 1 - Formula evaluation  
3. LHS = RHS ✓ - Base case verified

Inductive Step:
Assume: ∑ᵢ₌₁ᵏ i = k(k+1)/2 for some k ≥ 1
To Prove: ∑ᵢ₌₁ᵏ⁺¹ i = (k+1)(k+2)/2

4. ∑ᵢ₌₁ᵏ⁺¹ i = ∑ᵢ₌₁ᵏ i + (k+1) - Expanding sum
5. = k(k+1)/2 + (k+1) - Inductive hypothesis
6. = (k+1)[k/2 + 1] - Factoring
7. = (k+1)(k+2)/2 - Simplification
8. Therefore, P(k+1) is true - Inductive step complete

Conclusion: By mathematical induction, the formula holds for all n ≥ 1 ∎
```
```

## Natural Deduction Rules

### Basic Inference Rules
```example
```natural-deduction
Modus Ponens:
P → Q    P
─────────
    Q

Modus Tollens:  
P → Q    ¬Q
─────────
    ¬P

Hypothetical Syllogism:
P → Q    Q → R  
─────────────
     P → R
```
```

### Quantifier Rules
```example
```natural-deduction
Universal Instantiation:
∀x P(x)
─────────
 P(a)

Universal Generalization:
P(a) [where a is arbitrary]
──────────────────────
      ∀x P(x)

Existential Instantiation:
∃x P(x)
─────────────────
P(c) [for new constant c]

Existential Generalization:
P(a)
─────────
∃x P(x)
```
```

## Advanced Proof Techniques

### Proof by Cases
```example
```proof
Theorem: For any integer n, n² - n is even
To Prove: ∀n ∈ ℤ, 2 | (n² - n)

Proof by Cases:
Case 1: n is even
1. n = 2k for some integer k - Assumption
2. n² - n = (2k)² - 2k = 4k² - 2k = 2(2k² - k) - Algebraic manipulation
3. Since (2k² - k) is an integer, n² - n is even ✓

Case 2: n is odd  
1. n = 2k + 1 for some integer k - Assumption
2. n² - n = (2k + 1)² - (2k + 1) - Substitution
3. = 4k² + 4k + 1 - 2k - 1 - Expansion
4. = 4k² + 2k = 2(2k² + k) - Simplification
5. Since (2k² + k) is an integer, n² - n is even ✓

Conclusion: In both cases, n² - n is even ∎
```
```

### Constructive Proof
```example
```proof
Theorem: For any two rational numbers r and s, there exists a rational number between them
Given: r, s ∈ ℚ with r < s
To Prove: ∃t ∈ ℚ such that r < t < s

Constructive Proof:
1. Let t = (r + s)/2 - Construction
2. r = r/2 + r/2 < r/2 + s/2 = (r + s)/2 = t - Since r < s
3. t = (r + s)/2 < s/2 + s/2 = s - Since r < s  
4. Since r, s ∈ ℚ, we have t = (r + s)/2 ∈ ℚ - Closure under arithmetic
5. Therefore, t is rational and r < t < s ∎
```
```

## Proof Verification Patterns

### Soundness Check
```example
```verification
Proof Soundness Criteria:
1. ∀step(ValidInference(step)) - Each step follows valid inference rules
2. ∀premise(Justified(premise)) - All premises are established  
3. LogicalFlow(proof) - Steps form coherent logical progression
4. Complete(proof) - No logical gaps between premises and conclusion
```
```

### Completeness Analysis
```example
```verification
Completeness Assessment:
1. AllCasesConsidered(proof) - Exhaustive case analysis when needed
2. NoAssumptionsUnstated(proof) - All assumptions explicitly stated
3. ConclusionFollows(premises, conclusion) - Conclusion logically follows
4. NoCircularReasoning(proof) - No circular dependencies in logic
```
```

## Integration with Other Systems

### Algorithm Correctness Proofs
```example
```algorithm-proof
Algorithm: BinarySearch(array A, target x)
Precondition: A is sorted in ascending order
Postcondition: Returns index i such that A[i] = x, or -1 if x ∉ A

Correctness Proof:
Loop Invariant: A[low..high] contains x if x ∈ A
1. Initialization: Invariant true when low = 0, high = length(A) - 1
2. Maintenance: Each iteration preserves invariant while reducing search space
3. Termination: Loop terminates when low > high or element found
4. Correctness: Upon termination, element found or proven absent ∎
```
```

### System Property Verification
```example
```system-proof  
Property: Mutual Exclusion in Critical Section
System: Two processes P₁, P₂ accessing shared resource
To Prove: ¬(InCritical(P₁) ∧ InCritical(P₂))

State Space Analysis:
1. States: {Idle, Waiting, Critical} for each process
2. Transitions: Governed by synchronization protocol
3. Invariant: At most one process in Critical state
4. Proof by state space enumeration and transition analysis ∎
```
```

## Proof Documentation Standards

### Structured Format
```example
```proof-template
Theorem: [Statement]
Context: [Background assumptions]
Significance: [Why this matters]

Proof Strategy: [High-level approach]
Key Insights: [Important observations]

Detailed Proof:
[Step-by-step argumentation]

Verification: [Soundness checks]
Extensions: [Related results or generalizations] ∎
```
```

## See Also
- `./.claude/npl/instructing/symbolic-logic.md` - Symbolic notation systems
- `./.claude/npl/instructing/second-order.md` - Higher-order reasoning patterns  
- `./.claude/npl/instructing/alg-speak.md` - Algorithm specification and analysis
- `./.claude/npl/pumps/npl-cot.md` - Chain of thought reasoning structures