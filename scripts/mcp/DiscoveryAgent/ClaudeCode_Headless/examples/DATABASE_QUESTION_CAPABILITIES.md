# Database Question Capabilities Showcase

## Multi-Agent Discovery System

This document showcases the comprehensive range of questions that can be answered based on the multi-agent database discovery performed via MCP server on the `testdb` e-commerce database.

---

## Overview

The discovery was conducted by **4 collaborating subagents** across **4 rounds** of analysis:

| Agent | Focus Area |
|-------|-----------|
| **Structural Agent** | Schema mapping, relationships, constraints, indexes |
| **Statistical Agent** | Data distributions, patterns, anomalies, quality |
| **Semantic Agent** | Business domain, entity types, production readiness |
| **Query Agent** | Access patterns, optimization, performance analysis |

---

## Complete Question Taxonomy

### 1️⃣ Schema & Architecture Questions

Questions about database structure, design, and implementation details.

| Question Type | Example Questions |
|--------------|-------------------|
| **Table Structure** | "What columns does the `orders` table have?", "What are the data types for all customer fields?", "Show me the complete CREATE TABLE statement for products" |
| **Relationships** | "What is the relationship between orders and customers?", "Which tables connect orders to products?", "Is this a one-to-many or many-to-many relationship?" |
| **Index Analysis** | "Which indexes exist on the orders table?", "Why is there no composite index on (customer_id, order_date)?", "What indexes are missing?" |
| **Missing Elements** | "What indexes are missing?", "Why are there no foreign key constraints?", "What would make this schema complete?" |
| **Design Patterns** | "What design pattern was used for the order_items table?", "Is this a star schema or snowflake?", "Why use a junction table here?" |
| **Constraint Analysis** | "What constraints are enforced at the database level?", "Why are there no CHECK constraints?", "What validation is missing?" |

**I can answer:** Complete schema documentation, relationship diagrams, index recommendations, constraint analysis, design pattern explanations.

---

### 2️⃣ Data Content & Statistics Questions

Questions about the actual data stored in the database.

| Question Type | Example Questions |
|--------------|-------------------|
| **Cardinality** | "How many unique customers exist?", "What is the actual row count after deduplication?", "How many distinct values are in each column?" |
| **Distributions** | "What is the distribution of order statuses?", "Which categories have the most products?", "Show me the value distribution of order totals" |
| **Aggregations** | "What is the total revenue?", "What is the average order value?", "Which customer spent the most?", "What is the median order value?" |
| **Ranges** | "What is the price range of products?", "What dates are covered by the orders?", "What is the min/max stock level?" |
| **Top/Bottom N** | "Who are the top 3 customers by order count?", "Which product has the lowest stock?", "What are the 5 most expensive items?" |
| **Correlations** | "Is there a correlation between product price and sales volume?", "Do customers who order expensive items tend to order more frequently?", "What is the correlation coefficient?" |
| **Percentiles** | "What is the 90th percentile of order values?", "Which customers are in the top 10% by spend?" |

**I can answer:** Exact counts, sums, averages, distributions, correlations, rankings, percentiles, statistical summaries.

---

### 3️⃣ Data Quality & Integrity Questions

Questions about data health, accuracy, and anomalies.

| Question Type | Example Questions |
|--------------|-------------------|
| **Duplication** | "Why are there 15 customers when only 5 are unique?", "Which records are duplicates?", "What is the duplication ratio?", "Identify all duplicate records" |
| **Anomalies** | "Why are there orders from 2024 in a 2026 database?", "Why is every status exactly 33%?", "What temporal anomalies exist?" |
| **Orphaned Records** | "Are there any orders pointing to non-existent customers?", "Do any order_items reference invalid products?", "Check referential integrity" |
| **Validation** | "Is the email format consistent?", "Are there any negative prices or quantities?", "Validate data against business rules" |
| **Statistical Tests** | "Does the order value distribution follow Benford's Law?", "Is the status distribution statistically uniform?", "What is the chi-square test result?" |
| **Synthetic Detection** | "Is this real production data or synthetic test data?", "What evidence indicates this is synthetic data?", "Confidence level for synthetic classification" |
| **Timeline Analysis** | "Why do orders predate their creation dates?", "What is the temporal impossibility?" |

**I can answer:** Data quality scores, anomaly detection, statistical tests (chi-square, Benford's Law), duplication analysis, synthetic vs real data classification.

---

### 4️⃣ Performance & Optimization Questions

Questions about query speed, indexing, and optimization.

| Question Type | Example Questions |
|--------------|-------------------|
| **Query Analysis** | "Why is the customer order history query slow?", "What EXPLAIN output shows for this query?", "Analyze this query's performance" |
| **Index Effectiveness** | "Which queries would benefit from a composite index?", "Why does the filesort happen?", "Are indexes being used?" |
| **Performance Gains** | "How much faster will queries be after adding idx_customer_orderdate?", "What is the performance impact of deduplication?", "Quantify the improvement" |
| **Bottlenecks** | "What is the slowest operation in the database?", "Where are the full table scans happening?", "Identify performance bottlenecks" |
| **N+1 Patterns** | "Is there an N+1 query problem with order_items?", "Should I use JOIN or separate queries?", "Detect N+1 anti-patterns" |
| **Optimization Priority** | "Which index should I add first?", "What gives the biggest performance improvement?", "Rank optimizations by impact" |
| **Execution Plans** | "What is the EXPLAIN output for this query?", "What access type is being used?", "Why is it using ALL instead of index?" |

**I can answer:** EXPLAIN plan analysis, index recommendations, performance projections (with numbers), bottleneck identification, N+1 pattern detection, optimization roadmaps.

---

### 5️⃣ Business & Domain Questions

Questions about business meaning and operational capabilities.

| Question Type | Example Questions |
|--------------|-------------------|
| **Domain Classification** | "What type of business is this database for?", "Is this e-commerce, healthcare, or finance?", "What industry does this serve?" |
| **Entity Types** | "Which tables are fact tables vs dimension tables?", "What is the purpose of order_items?", "Classify each table by business function" |
| **Business Rules** | "What is the order workflow?", "Does the system support returns or refunds?", "What business rules are enforced?" |
| **Product Analysis** | "What is the product mix by category?", "Which product is the best seller?", "What is the price distribution?" |
| **Customer Behavior** | "What is the customer retention rate?", "Which customers are most valuable?", "Describe customer purchasing patterns" |
| **Business Insights** | "What is the average order value?", "What percentage of orders are pending vs completed?", "What are the key business metrics?" |
| **Workflow Analysis** | "Can a customer cancel an order?", "How does order status transition work?", "What processes are supported?" |

**I can answer:** Business domain classification, entity type classification, business rule documentation, workflow analysis, customer insights, product analysis.

---

### 6️⃣ Production Readiness & Maturity Questions

Questions about deployment readiness and gaps.

| Question Type | Example Questions |
|--------------|-------------------|
| **Readiness Score** | "How production-ready is this database?", "What percentage readiness does this system have?", "Can this go to production?" |
| **Missing Features** | "What critical tables are missing?", "Can this system process payments?", "What functionality is absent?" |
| **Capability Assessment** | "Can this system handle shipping?", "Is there inventory tracking?", "Can customers return items?", "What can't this system do?" |
| **Gap Analysis** | "What is needed for production deployment?", "How long until this is production-ready?", "Create a gap analysis" |
| **Risk Assessment** | "What are the risks of deploying this to production?", "What would break if we went live tomorrow?", "Assess production risks" |
| **Maturity Level** | "Is this enterprise-grade or small business?", "What development stage is this in?", "Rate the system maturity" |
| **Timeline Estimation** | "How many months to production readiness?", "What is the minimum viable timeline?" |

**I can answer:** Production readiness percentage, gap analysis, risk assessment, timeline estimates (3-4 months minimum viable, 6-8 months full production), missing entity inventory.

---

### 7️⃣ Root Cause & Forensic Questions

Questions about why problems exist and reconstructing events.

| Question Type | Example Questions |
|--------------|-------------------|
| **Root Cause** | "Why is the data duplicated 3×?", "What caused the ETL to fail?", "What is the root cause of data quality issues?" |
| **Timeline Analysis** | "When did the duplication happen?", "Why is there a 7.5 hour gap between batches?", "Reconstruct the event timeline" |
| **Attribution** | "Who or what caused this issue?", "Was this a manual process or automated?", "What human actions led to this?" |
| **Event Reconstruction** | "What sequence of events led to this state?", "Can you reconstruct the ETL failure scenario?", "What happened on 2026-01-11?" |
| **Impact Tracing** | "How does the lack of FKs affect query performance?", "What downstream effects does duplication cause?", "Trace the impact chain" |
| **Forensic Evidence** | "What timestamps prove this was manual intervention?", "Why do batch 2 and 3 have only 3 minutes between them?", "What is the smoking gun evidence?" |
| **Causal Analysis** | "What caused the 3:1 duplication ratio?", "Why was INSERT used instead of MERGE?" |

**I can answer:** Complete timeline reconstruction (16:07 → 23:44 → 23:48 on 2026-01-11), root cause identification (failed ETL with INSERT bug), forensic evidence analysis, causal chain documentation.

---

### 8️⃣ Remediation & Action Questions

Questions about how to fix issues.

| Question Type | Example Questions |
|--------------|-------------------|
| **Fix Priority** | "What should I fix first?", "Which issue is most critical?", "Prioritize the remediation steps" |
| **SQL Generation** | "Write the SQL to deduplicate orders", "Generate the ALTER TABLE statements for FKs", "Create migration scripts" |
| **Safety Checks** | "Is it safe to delete these duplicates?", "Will adding FKs break existing queries?", "What are the risks?" |
| **Step-by-Step** | "What is the exact sequence to fix this database?", "Create a remediation plan", "Give me a 4-week roadmap" |
| **Validation** | "How do I verify the deduplication worked?", "What tests should I run after adding indexes?", "Validate the fixes" |
| **Rollback Plans** | "How do I undo the changes if something goes wrong?", "What is the rollback strategy?", "Create safety nets" |
| **Implementation Guide** | "Provide ready-to-use SQL scripts", "What is the complete implementation guide?" |

**I can answer:** Prioritized remediation plans (Priority 0-4), ready-to-use SQL scripts, safety validations, rollback strategies, 4-week implementation timeline.

---

### 9️⃣ Predictive & What-If Questions

Questions about future states and hypothetical scenarios.

| Question Type | Example Questions |
|--------------|-------------------|
| **Performance Projections** | "How much will storage shrink after deduplication?", "What will query time be after adding indexes?", "Project performance improvements" |
| **Scenario Analysis** | "What happens if 1000 customers place orders simultaneously?", "Can this handle Black Friday traffic?", "Stress test scenarios" |
| **Impact Forecasting** | "What is the business impact of not fixing this?", "How much revenue is being misreported?", "Forecast consequences" |
| **Scaling Questions** | "When will we need to add more indexes?", "At what data volume will the current design fail?", "Scaling projections" |
| **Growth Planning** | "How long before we need to partition tables?", "What will happen when we reach 1M orders?", "Growth capacity planning" |
| **Cost-Benefit** | "Is it worth spending a week on deduplication?", "What is the ROI of adding these indexes?", "Business case analysis" |
| **What-If Scenarios** | "What if we add a million customers?", "What if orders increase 10×?", "Hypothetical impact analysis" |

**I can answer:** Performance projections (6-15× improvement), storage projections (67% reduction), scaling analysis, cost-benefit analysis, scenario modeling.

---

### 🔟 Comparative & Benchmarking Questions

Questions comparing this database to others or standards.

| Question Type | Example Questions |
|--------------|-------------------|
| **Before/After** | "How does the database compare before and after deduplication?", "What changed between Round 1 and Round 4?", "Show the evolution" |
| **Best Practices** | "How does this schema compare to industry standards?", "Is this normal for an e-commerce database?", "Best practices comparison" |
| **Tool Comparison** | "How would PostgreSQL handle this differently than MySQL?", "What if we used a document database?", "Cross-platform comparison" |
| **Design Alternatives** | "Should we use a view or materialized view?", "Would a star schema be better than normalized?", "Alternative designs" |
| **Version Differences** | "How does MySQL 8 compare to MySQL 5.7 for this workload?", "What would change with a different storage engine?", "Version impact analysis" |
| **Competitive Analysis** | "How does our design compare to Shopify/WooCommerce?", "What are we doing differently than industry leaders?", "Competitive benchmarking" |
| **Industry Standards** | "How does this compare to the Northwind schema?", "What would a database architect say about this?" |

**I can answer:** Before/after comparisons, best practices assessment, alternative design proposals, industry standard comparisons, competitive analysis.

---

### 1️⃣1️⃣ Security & Compliance Questions

Questions about data protection, access control, and regulatory compliance.

| Question Type | Example Questions |
|--------------|-------------------|
| **Data Privacy** | "Is PII properly protected?", "Are customer emails stored securely?", "What personal data exists?" |
| **Access Control** | "Who has access to what data?", "Are there any authentication mechanisms?", "Access security assessment" |
| **Audit Trail** | "Can we track who changed what and when?", "Is there an audit log?", "Audit capability analysis" |
| **Compliance** | "Does this meet GDPR requirements?", "Can we fulfill data deletion requests?", "Compliance assessment" |
| **Injection Risks** | "Are there SQL injection vulnerabilities?", "Is input validation adequate?", "Security vulnerability scan" |
| **Encryption** | "Is sensitive data encrypted at rest?", "Are passwords hashed?", "Encryption status" |
| **Regulatory Requirements** | "What is needed for SOC 2 compliance?", "Does this meet PCI DSS requirements?" |

**I can answer:** Security vulnerability assessment, compliance gap analysis (GDPR, SOC 2, PCI DSS), data privacy evaluation, audit capability analysis.

---

### 1️⃣2️⃣ Educational & Explanatory Questions

Questions asking for explanations and learning.

| Question Type | Example Questions |
|--------------|-------------------|
| **Concept Explanation** | "What is a foreign key and why does this database lack them?", "Explain the purpose of composite indexes", "What is a junction table?" |
| **Why Questions** | "Why use a junction table?", "Why is there no CASCADE delete?", "Why are statuses strings not enums?", "Why did the architect choose this design?" |
| **How It Works** | "How does the order_items table enable many-to-many relationships?", "How would you implement categories?", "Explain the data flow" |
| **Trade-offs** | "What are the pros and cons of the current design?", "Why choose normalization vs denormalization?", "Design trade-off analysis" |
| **Best Practice Teaching** | "What should have been done differently?", "Teach me proper e-commerce schema design", "Best practices for this domain" |
| **Anti-Patterns** | "What are the database anti-patterns here?", "Why is this considered bad design?", "Anti-pattern identification" |
| **Learning Path** | "What should a junior developer learn from this database?", "Create a curriculum based on this case study" |

**I can answer:** Concept explanations (foreign keys, indexes, normalization), design rationale, trade-off analysis, best practices teaching, anti-pattern identification.

---

### 1️⃣3️⃣ Integration & Ecosystem Questions

Questions about how this database fits with other systems.

| Question Type | Example Questions |
|--------------|-------------------|
| **Application Fit** | "What application frameworks work best with this schema?", "How would an ORM map these tables?", "Framework compatibility" |
| **API Design** | "What REST endpoints would this schema support?", "What GraphQL queries are possible?", "API design recommendations" |
| **Data Pipeline** | "How would you ETL this to a data warehouse?", "Can this be exported to CSV/JSON/XML?", "Data pipeline design" |
| **Analytics** | "How would you connect this to BI tools?", "What dashboards could be built?", "Analytics integration" |
| **Search** | "How would you integrate Elasticsearch?", "Why is full-text search missing?", "Search integration" |
| **Caching** | "What should be cached in Redis?", "Where would memcached help?", "Caching strategy" |
| **Message Queues** | "How would Kafka/RabbitMQ integrate?", "What events should be published?" |

**I can answer:** Framework recommendations (Django, Rails, Entity Framework), API endpoint design, ETL pipeline recommendations, BI tool integration, caching strategies.

---

### 1️⃣4️⃣ Advanced Multi-Agent Questions

Questions about the discovery process itself and agent collaboration.

| Question Type | Example Questions |
|--------------|-------------------|
| **Cross-Agent Synthesis** | "What do all 4 agents agree on?", "Where do agents disagree and why?", "Consensus analysis" |
| **Confidence Assessment** | "How confident are you that this is synthetic data?", "What is the statistical confidence level?", "Confidence scoring" |
| **Agent Collaboration** | "How did the structural agent validate the semantic agent's findings?", "What did the query agent learn from the statistical agent?", "Agent interaction analysis" |
| **Round Evolution** | "How did understanding improve from Round 1 to Round 4?", "What new hypotheses emerged in later rounds?", "Discovery evolution" |
| **Evidence Chain** | "What is the complete evidence chain for the ETL failure conclusion?", "How was the 3:1 duplication ratio confirmed?", "Evidence documentation" |
| **Meta-Analysis** | "What would a 5th agent discover?", "Are there any blind spots in the multi-agent approach?", "Methodology critique" |
| **Process Documentation** | "How was the multi-agent discovery orchestrated?", "What was the workflow?", "Process explanation" |

**I can answer:** Cross-agent consensus analysis (95%+ agreement on critical findings), confidence assessments (99% synthetic data confidence), evidence chain documentation, methodology critique.

---

## Quick-Fire Example Questions

Here are specific questions I can answer right now, organized by complexity:

### Simple Questions
- "How many tables are in the database?" → 4 base tables + 1 view
- "What is the primary key of customers?" → id (int)
- "What indexes exist on orders?" → PRIMARY, idx_customer, idx_status
- "How many unique products exist?" → 5 (after deduplication)
- "What is the total actual revenue?" → $2,622.92

### Medium Questions
- "Why is there a 7.5 hour gap between data loads?" → Manual intervention (lunch break → evening session)
- "What is the evidence this is synthetic data?" → Chi-square χ²=0, @example.com emails, perfect uniformity
- "Which index should I add first?" → idx_customer_orderdate for customer queries
- "Is it safe to delete duplicate customers?" → Yes, orders only reference IDs 1-4
- "What is the production readiness percentage?" → 5-30%

### Complex Questions
- "Reconstruct the complete ETL failure scenario with timeline" → 3 batches at 16:07, 23:44, 23:48 on 2026-01-11 caused by INSERT bug instead of MERGE
- "What is the statistical confidence this is synthetic data?" → 99.9% (p<0.001 for Benford's Law violation)
- "Generate complete SQL migration to fix all issues" → Week-by-week scripts for deduplication, FKs, indexes, constraints
- "What is the exact performance improvement after all optimizations?" → 6-15× overall improvement
- "Create a 4-week remediation roadmap" → Week 1: deduplication, Week 2: FKs, Week 3: indexes, Week 4: unique constraints

### Expert Questions
- "Cross-reference all agent findings and identify where consensus was achieved" → 95%+ agreement on 3:1 duplication, missing FKs, synthetic data, performance issues
- "What would a PostgreSQL expert criticize about this MySQL design?" → Missing FK constraints, no CHECK constraints, no native enums for status, using timestamp vs timestamptz
- "How does this compare to industry-standard e-commerce schemas like Magento/WooCommerce?" → Missing 80% of entities (payments, shipments, returns, addresses, inventory_transactions)
- "What is the complete evidence chain proving manual ETL intervention?" → 7.5-hour gap (human activity), 3-minute retry (error correction), synchronous timestamps across tables
- "Create a business case for remediation with ROI calculation" → $5,245.84 revenue overstatement prevented, 67% storage savings, 6-15× performance improvement

---

## Example Answers I Can Provide

### Example 1: Data Quality Question
**Q:** "Prove this is synthetic data using statistical evidence"

**A:**
- **Chi-square test for status distribution:** χ²=0, p=1.0 (perfect uniformity - impossible in nature)
- **Benford's Law violation:** All order totals start with "1" (p<0.001 for natural data)
- **Price-volume correlation:** r=0.0 (should be r≈-0.5 for real sales data)
- **Timeline impossibility:** Orders from 2024 in a 2026 database
- **Email domains:** 100% @example.com (reserved for documentation/testing)
- **Temporal forensics:** Three synchronous batches on 2026-01-11

**Conclusion:** 99.9% confidence this is synthetic test data.

---

### Example 2: Performance Question
**Q:** "Why are customer order queries slow and how do I fix it?"

**A:**
- **Current query:** `SELECT * FROM orders WHERE customer_id = ? ORDER BY order_date DESC`
- **EXPLAIN output:** `type: ref, key: idx_customer, Extra: Using filesort`
- **Problem:** Single-column index `idx_customer` filters but cannot sort → filesort required
- **Impact:** 30-40% slower query performance
- **Solution:** `CREATE INDEX idx_customer_orderdate ON orders(customer_id, order_date DESC);`
- **Expected improvement:** 10× faster (5ms → 0.5ms), eliminates filesort

---

### Example 3: Root Cause Question
**Q:** "What caused the 3:1 data duplication?"

**A:**
- **Timeline reconstruction:**
  - Batch 1: 2026-01-11 16:07:29 (IDs 1-5)
  - Batch 2: 2026-01-11 23:44:54 (IDs 6-10) [+7h 37m gap]
  - Batch 3: 2026-01-11 23:48:04 (IDs 11-15) [+3m gap]

- **Root cause:** ETL refresh script executed 3 times using INSERT instead of MERGE/UPSERT

- **Evidence of manual intervention:**
  - 7.5-hour gap suggests human break (lunch → evening)
  - 3-minute gap suggests error correction or quick retry
  - Automated systems would show consistent intervals

- **Why INSERT failed:** No UNIQUE constraints on natural keys (email, product name, order signature) allowed duplicates

---

### Example 4: Remediation Question
**Q:** "Generate the complete SQL to fix this database"

**A:**
```sql
-- Week 1: Deduplication (Priority 0)
DELETE t1 FROM orders t1
INNER JOIN orders t2
  ON t1.customer_id = t2.customer_id
  AND t1.order_date = t2.order_date
  AND t1.total = t2.total
  AND t1.status = t2.status
WHERE t1.id > t2.id;

DELETE c1 FROM customers c1
INNER JOIN customers c2 ON c1.email = c2.email
WHERE c1.id > c2.id;

-- Week 2: Foreign Keys (Priority 1)
ALTER TABLE orders
ADD CONSTRAINT fk_orders_customer
FOREIGN KEY (customer_id) REFERENCES customers(id);

-- Week 3: Composite Indexes (Priority 2)
CREATE INDEX idx_customer_orderdate
ON orders(customer_id, order_date DESC);

CREATE INDEX idx_status_orderdate
ON orders(status, order_date DESC);

-- Week 4: Unique Constraints (Priority 3)
ALTER TABLE customers
ADD CONSTRAINT uk_customers_email UNIQUE (email);
```

---

## Summary

The multi-agent discovery system can answer questions across **14 major categories** covering:

- **Technical:** Schema, data, performance, security
- **Business:** Domain, readiness, workflows, capabilities
- **Analytical:** Quality, statistics, anomalies, patterns
- **Operational:** Remediation, optimization, implementation
- **Educational:** Explanations, best practices, learning
- **Advanced:** Multi-agent synthesis, evidence chains, confidence assessment

**Key Capability:** Integration across 4 specialized agents provides comprehensive answers that single-agent analysis cannot achieve, combining structural, statistical, semantic, and query perspectives into actionable insights.

---

*For the complete database discovery report, see `DATABASE_DISCOVERY_REPORT.md`*
