# Codebase Community Database - 40 Question Templates

## Template Structure
Each template includes:
- **Natural Language Question**: How users would ask it
- **SQL Template**: Parameterized query structure
- **Example SQL**: Concrete implementation
- **Domain**: Business domain classification
- **Complexity**: Simple/Medium/Complex

---

## USER ANALYTICS TEMPLATES (10 questions)

### Template 1: Top Users by Reputation
**Natural Language**: "Who are the top N users by reputation?"
**Domain**: User Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  Id AS user_id,
  DisplayName,
  Reputation,
  Views AS profile_views,
  UpVotes,
  DownVotes
FROM codebase_community_template.users
WHERE Reputation > 0
ORDER BY Reputation DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT Id, DisplayName, Reputation, Views, UpVotes, DownVotes
FROM codebase_community_template.users
WHERE Reputation > 0
ORDER BY Reputation DESC
LIMIT 10;
```

---

### Template 2: User Activity Summary
**Natural Language**: "What is the activity summary for user {{user_id}}?"
**Domain**: User Analytics
**Complexity**: Medium

**SQL Template**:
```sql
SELECT
  u.Id,
  u.DisplayName,
  u.Reputation,
  COUNT(DISTINCT p.Id) AS post_count,
  COUNT(DISTINCT c.Id) AS comment_count,
  COUNT(DISTINCT v.Id) AS vote_count,
  COUNT(DISTINCT b.Id) AS badge_count
FROM codebase_community_template.users u
LEFT JOIN codebase_community_template.posts p ON u.Id = p.OwnerUserId
LEFT JOIN codebase_community_template.comments c ON u.Id = c.UserId
LEFT JOIN codebase_community_template.votes v ON u.Id = v.UserId
LEFT JOIN codebase_community_template.badges b ON u.Id = b.UserId
WHERE u.Id = {{user_id}}
GROUP BY u.Id, u.DisplayName, u.Reputation;
```

**Example**:
```sql
SELECT u.Id, u.DisplayName, u.Reputation,
  COUNT(DISTINCT p.Id) AS post_count,
  COUNT(DISTINCT c.Id) AS comment_count,
  COUNT(DISTINCT v.Id) AS vote_count,
  COUNT(DISTINCT b.Id) AS badge_count
FROM codebase_community_template.users u
LEFT JOIN codebase_community_template.posts p ON u.Id = p.OwnerUserId
LEFT JOIN codebase_community_template.comments c ON u.Id = c.UserId
LEFT JOIN codebase_community_template.votes v ON u.Id = v.UserId
LEFT JOIN codebase_community_template.badges b ON u.Id = b.UserId
WHERE u.Id = 8
GROUP BY u.Id, u.DisplayName, u.Reputation;
```

---

### Template 3: User Registration Trends
**Natural Language**: "How many users joined each month in {{year}}?"
**Domain**: User Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  DATE_FORMAT(CreationDate, '%Y-%m') AS month,
  COUNT(*) AS new_users
FROM codebase_community_template.users
WHERE YEAR(CreationDate) = {{year}}
GROUP BY DATE_FORMAT(CreationDate, '%Y-%m')
ORDER BY month;
```

**Example**:
```sql
SELECT
  DATE_FORMAT(CreationDate, '%Y-%m') AS month,
  COUNT(*) AS new_users
FROM codebase_community_template.users
WHERE YEAR(CreationDate) = 2010
GROUP BY DATE_FORMAT(CreationDate, '%Y-%m')
ORDER BY month;
```

---

### Template 4: Most Active Users by Posts
**Natural Language**: "Who are the most active users in the past {{days}} days?"
**Domain**: User Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  u.Id,
  u.DisplayName,
  COUNT(p.Id) AS post_count
FROM codebase_community_template.users u
INNER JOIN codebase_community_template.posts p ON u.Id = p.OwnerUserId
WHERE p.CreaionDate >= DATE_SUB(CURDATE(), INTERVAL {{days}} DAY)
GROUP BY u.Id, u.DisplayName
ORDER BY post_count DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT u.Id, u.DisplayName, COUNT(p.Id) AS post_count
FROM codebase_community_template.users u
INNER JOIN codebase_community_template.posts p ON u.Id = p.OwnerUserId
WHERE p.CreaionDate >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
GROUP BY u.Id, u.DisplayName
ORDER BY post_count DESC
LIMIT 10;
```

---

### Template 5: User Answer Acceptance Rate
**Natural Language**: "What is the answer acceptance rate for users with at least {{min_answers}} answers?"
**Domain**: User Analytics
**Complexity**: Medium

**SQL Template**:
```sql
WITH user_answers AS (
  SELECT
    a.OwnerUserId,
    COUNT(*) AS total_answers,
    SUM(CASE WHEN q.AcceptedAnswerId = a.Id THEN 1 ELSE 0 END) AS accepted_answers
  FROM codebase_community_template.posts a
  INNER JOIN codebase_community_template.posts q ON a.ParentId = q.Id
  WHERE a.PostTypeId = 2
    AND q.PostTypeId = 1
    AND a.OwnerUserId IS NOT NULL
  GROUP BY a.OwnerUserId
  HAVING COUNT(*) >= {{min_answers}}
)
SELECT
  u.DisplayName,
  ua.total_answers,
  ua.accepted_answers,
  ROUND(ua.accepted_answers * 100.0 / ua.total_answers, 2) AS acceptance_rate_pct
FROM user_answers ua
INNER JOIN codebase_community_template.users u ON ua.OwnerUserId = u.Id
ORDER BY acceptance_rate_pct DESC
LIMIT {{N}};
```

**Example**:
```sql
WITH user_answers AS (
  SELECT
    a.OwnerUserId,
    COUNT(*) AS total_answers,
    SUM(CASE WHEN q.AcceptedAnswerId = a.Id THEN 1 ELSE 0 END) AS accepted_answers
  FROM codebase_community_template.posts a
  INNER JOIN codebase_community_template.posts q ON a.ParentId = q.Id
  WHERE a.PostTypeId = 2 AND q.PostTypeId = 1 AND a.OwnerUserId IS NOT NULL
  GROUP BY a.OwnerUserId
  HAVING COUNT(*) >= 10
)
SELECT
  u.DisplayName,
  ua.total_answers,
  ua.accepted_answers,
  ROUND(ua.accepted_answers * 100.0 / ua.total_answers, 2) AS acceptance_rate_pct
FROM user_answers ua
INNER JOIN codebase_community_template.users u ON ua.OwnerUserId = u.Id
ORDER BY acceptance_rate_pct DESC
LIMIT 20;
```

---

### Template 6: Users by Reputation Range
**Natural Language**: "How many users have reputation between {{min_rep}} and {{max_rep}}?"
**Domain**: User Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  COUNT(*) AS user_count
FROM codebase_community_template.users
WHERE Reputation >= {{min_rep}} AND Reputation <= {{max_rep}};
```

**Example**:
```sql
SELECT COUNT(*) AS user_count
FROM codebase_community_template.users
WHERE Reputation >= 100 AND Reputation <= 500;
```

---

### Template 7: User Badges Summary
**Natural Language**: "What badges has user {{user_id}} earned?"
**Domain**: User Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  b.Name AS badge_name,
  b.[Date] AS earned_date,
  u.DisplayName
FROM codebase_community_template.badges b
INNER JOIN codebase_community_template.users u ON b.UserId = u.Id
WHERE b.UserId = {{user_id}}
ORDER BY b.[Date] DESC;
```

**Example**:
```sql
SELECT b.Name AS badge_name, b.[Date] AS earned_date, u.DisplayName
FROM codebase_community_template.badges b
INNER JOIN codebase_community_template.users u ON b.UserId = u.Id
WHERE b.UserId = 8
ORDER BY b.[Date] DESC;
```

---

### Template 8: Top Badge Earners
**Natural Language**: "Who has earned the most badges?"
**Domain**: User Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  u.Id,
  u.DisplayName,
  COUNT(b.Id) AS badge_count
FROM codebase_community_template.users u
INNER JOIN codebase_community_template.badges b ON u.Id = b.UserId
GROUP BY u.Id, u.DisplayName
ORDER BY badge_count DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT u.Id, u.DisplayName, COUNT(b.Id) AS badge_count
FROM codebase_community_template.users u
INNER JOIN codebase_community_template.badges b ON u.Id = b.UserId
GROUP BY u.Id, u.DisplayName
ORDER BY badge_count DESC
LIMIT 20;
```

---

### Template 9: User Voting Behavior
**Natural Language**: "What is the voting behavior for user {{user_id}}?"
**Domain**: User Analytics
**Complexity**: Medium

**SQL Template**:
```sql
SELECT
  u.DisplayName,
  u.UpVotes,
  u.DownVotes,
  (u.UpVotes + u.DownVotes) AS total_votes,
  CASE
    WHEN (u.UpVotes + u.DownVotes) > 0
    THEN ROUND(u.UpVotes * 100.0 / (u.UpVotes + u.DownVotes), 2)
    ELSE 0
  END AS upvote_percentage
FROM codebase_community_template.users u
WHERE u.Id = {{user_id}};
```

**Example**:
```sql
SELECT u.DisplayName, u.UpVotes, u.DownVotes,
  (u.UpVotes + u.DownVotes) AS total_votes,
  CASE WHEN (u.UpVotes + u.DownVotes) > 0
    THEN ROUND(u.UpVotes * 100.0 / (u.UpVotes + u.DownVotes), 2)
    ELSE 0
  END AS upvote_percentage
FROM codebase_community_template.users u
WHERE u.Id = 8;
```

---

### Template 10: User Geographic Distribution
**Natural Language**: "How many users are from each location?"
**Domain**: User Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  Location,
  COUNT(*) AS user_count
FROM codebase_community_template.users
WHERE Location IS NOT NULL AND Location != ''
GROUP BY Location
ORDER BY user_count DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT Location, COUNT(*) AS user_count
FROM codebase_community_template.users
WHERE Location IS NOT NULL AND Location != ''
GROUP BY Location
ORDER BY user_count DESC
LIMIT 20;
```

---

## CONTENT ANALYTICS TEMPLATES (10 questions)

### Template 11: Most Viewed Questions
**Natural Language**: "What are the most viewed questions about {{tag}}?"
**Domain**: Content Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  Id,
  Title,
  ViewCount,
  Score,
  AnswerCount,
  CreaionDate
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND Tags LIKE '%<{{tag}}>%'
ORDER BY ViewCount DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT Id, Title, ViewCount, Score, AnswerCount, CreaionDate
FROM codebase_community_template.posts
WHERE PostTypeId = 1 AND Tags LIKE '%<bayesian>%'
ORDER BY ViewCount DESC
LIMIT 10;
```

---

### Template 12: Questions Without Answers
**Natural Language**: "What questions about {{tag}} have no answers?"
**Domain**: Content Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  Id,
  Title,
  CreaionDate,
  ViewCount,
  Score
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND AnswerCount = 0
  AND Tags LIKE '%<{{tag}}>%'
ORDER BY CreaionDate DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT Id, Title, CreaionDate, ViewCount, Score
FROM codebase_community_template.posts
WHERE PostTypeId = 1 AND AnswerCount = 0 AND Tags LIKE '%<python>%'
ORDER BY CreaionDate DESC
LIMIT 20;
```

---

### Template 13: Highest Scored Posts
**Natural Language**: "What are the highest scored posts in the past {{days}} days?"
**Domain**: Content Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  Id,
  CASE
    WHEN PostTypeId = 1 THEN Title
    ELSE 'Answer'
  END AS title,
  PostTypeId,
  Score,
  ViewCount,
  CreaionDate
FROM codebase_community_template.posts
WHERE CreaionDate >= DATE_SUB(CURDATE(), INTERVAL {{days}} DAY)
ORDER BY Score DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT Id,
  CASE WHEN PostTypeId = 1 THEN Title ELSE 'Answer' END AS title,
  PostTypeId, Score, ViewCount, CreaionDate
FROM codebase_community_template.posts
WHERE CreaionDate >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
ORDER BY Score DESC
LIMIT 20;
```

---

### Template 14: Questions by Time Period
**Natural Language**: "How many questions were created per day in the last {{days}} days?"
**Domain**: Content Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  DATE(CreaionDate) AS question_date,
  COUNT(*) AS question_count
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND CreaionDate >= DATE_SUB(CURDATE(), INTERVAL {{days}} DAY)
GROUP BY DATE(CreaionDate)
ORDER BY question_date DESC;
```

**Example**:
```sql
SELECT DATE(CreaionDate) AS question_date, COUNT(*) AS question_count
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND CreaionDate >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
GROUP BY DATE(CreaionDate)
ORDER BY question_date DESC;
```

---

### Template 15: Answer Quality Comparison
**Natural Language**: "How do accepted answers compare to non-accepted answers for {{tag}} questions?"
**Domain**: Content Analytics
**Complexity**: Medium

**SQL Template**:
```sql
WITH answer_stats AS (
  SELECT
    a.Id,
    a.Score,
    CASE WHEN q.AcceptedAnswerId = a.Id THEN 'accepted' ELSE 'not_accepted' END AS status
  FROM codebase_community_template.posts a
  INNER JOIN codebase_community_template.posts q ON a.ParentId = q.Id
  WHERE a.PostTypeId = 2
    AND q.PostTypeId = 1
    AND q.Tags LIKE '%<{{tag}}>%'
)
SELECT
  status,
  COUNT(*) AS answer_count,
  ROUND(AVG(Score), 2) AS avg_score,
  SUM(CASE WHEN Score > 0 THEN 1 ELSE 0 END) AS positive_count
FROM answer_stats
GROUP BY status;
```

**Example**:
```sql
WITH answer_stats AS (
  SELECT
    a.Id,
    a.Score,
    CASE WHEN q.AcceptedAnswerId = a.Id THEN 'accepted' ELSE 'not_accepted' END AS status
  FROM codebase_community_template.posts a
  INNER JOIN codebase_community_template.posts q ON a.ParentId = q.Id
  WHERE a.PostTypeId = 2 AND q.PostTypeId = 1 AND q.Tags LIKE '%<python>%'
)
SELECT
  status,
  COUNT(*) AS answer_count,
  ROUND(AVG(Score), 2) AS avg_score,
  SUM(CASE WHEN Score > 0 THEN 1 ELSE 0 END) AS positive_count
FROM answer_stats
GROUP BY status;
```

---

### Template 16: Average Answer Count
**Natural Language**: "What is the average number of answers per question for {{tag}}?"
**Domain**: Content Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  ROUND(AVG(AnswerCount), 2) AS avg_answers,
  ROUND(PERCENTILE_CONT(0.50) OVER (), 2) AS median_answers,
  ROUND(PERCENTILE_CONT(0.75) OVER (), 2) AS p75_answers,
  COUNT(*) AS total_questions
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND Tags LIKE '%<{{tag}}>%';
```

**Example**:
```sql
SELECT ROUND(AVG(AnswerCount), 2) AS avg_answers,
  ROUND(PERCENTILE_CONT(0.50) OVER (), 2) AS median_answers,
  ROUND(PERCENTILE_CONT(0.75) OVER (), 2) AS p75_answers,
  COUNT(*) AS total_questions
FROM codebase_community_template.posts
WHERE PostTypeId = 1 AND Tags LIKE '%<r>%';
```

---

### Template 17: Questions with Most Answers
**Natural Language**: "What questions about {{tag}} have the most answers?"
**Domain**: Content Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  Id,
  Title,
  AnswerCount,
  ViewCount,
  Score,
  AcceptedAnswerId,
  CreaionDate
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND Tags LIKE '%<{{tag}}>%'
  AND AnswerCount > 0
ORDER BY AnswerCount DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT Id, Title, AnswerCount, ViewCount, Score, AcceptedAnswerId, CreaionDate
FROM codebase_community_template.posts
WHERE PostTypeId = 1 AND Tags LIKE '%<machine-learning>%'
ORDER BY AnswerCount DESC
LIMIT 10;
```

---

### Template 18: Post Edit History
**Natural Language**: "What is the edit history for post {{post_id}}?"
**Domain**: Content Analytics
**Complexity**: Medium

**SQL Template**:
```sql
SELECT
  ph.Id,
  ph.PostHistoryTypeId,
  ph.CreationDate,
  u.DisplayName AS editor_name,
  ph.Text,
  ph.Comment
FROM codebase_community_template.postHistory ph
LEFT JOIN codebase_community_template.users u ON ph.UserId = u.Id
WHERE ph.PostId = {{post_id}}
ORDER BY ph.CreationDate ASC;
```

**Example**:
```sql
SELECT ph.Id, ph.PostHistoryTypeId, ph.CreationDate,
  u.DisplayName AS editor_name, ph.Text, ph.Comment
FROM codebase_community_template.postHistory ph
LEFT JOIN codebase_community_template.users u ON ph.UserId = u.Id
WHERE ph.PostId = 1
ORDER BY ph.CreationDate ASC;
```

---

### Template 19: Related Questions
**Natural Language**: "What questions are related to post {{post_id}}?"
**Domain**: Content Analytics
**Complexity**: Medium

**SQL Template**:
```sql
SELECT
  pl.Id AS link_id,
  pl.CreationDate AS link_date,
  pl.LinkTypeId,
  p_rel.Id AS related_post_id,
  p_rel.Title AS related_title,
  p_rel.Score AS related_score,
  p_rel.AnswerCount
FROM codebase_community_template.postLinks pl
INNER JOIN codebase_community_template.posts p_rel ON pl.RelatedPostId = p_rel.Id
WHERE pl.PostId = {{post_id}}
ORDER BY pl.CreationDate DESC;
```

**Example**:
```sql
SELECT pl.Id AS link_id, pl.CreationDate AS link_date, pl.LinkTypeId,
  p_rel.Id AS related_post_id, p_rel.Title AS related_title,
  p_rel.Score AS related_score, p_rel.AnswerCount
FROM codebase_community_template.postLinks pl
INNER JOIN codebase_community_template.posts p_rel ON pl.RelatedPostId = p_rel.Id
WHERE pl.PostId = 1
ORDER BY pl.CreationDate DESC;
```

---

### Template 20: Community Wiki Posts
**Natural Language**: "What posts have become community wikis?"
**Domain**: Content Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  p.Id,
  CASE WHEN p.PostTypeId = 1 THEN p.Title ELSE 'Answer' END AS title,
  p.PostTypeId,
  p.CommunityOwnedDate,
  p.Score,
  u.DisplayName AS original_author
FROM codebase_community_template.posts p
INNER JOIN codebase_community_template.users u ON p.OwnerUserId = u.Id
WHERE p.CommunityOwnedDate IS NOT NULL
ORDER BY p.CommunityOwnedDate DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT p.Id,
  CASE WHEN p.PostTypeId = 1 THEN p.Title ELSE 'Answer' END AS title,
  p.PostTypeId, p.CommunityOwnedDate, p.Score,
  u.DisplayName AS original_author
FROM codebase_community_template.posts p
INNER JOIN codebase_community_template.users u ON p.OwnerUserId = u.Id
WHERE p.CommunityOwnedDate IS NOT NULL
ORDER BY p.CommunityOwnedDate DESC
LIMIT 20;
```

---

## ENGAGEMENT ANALYTICS TEMPLATES (10 questions)

### Template 21: Most Commented Posts
**Natural Language**: "What posts have the most comments?"
**Domain**: Engagement Analytics
**Complexity**: Medium

**SQL Template**:
```sql
SELECT
  p.Id,
  CASE WHEN p.PostTypeId = 1 THEN p.Title ELSE 'Answer' END AS title,
  p.PostTypeId,
  COUNT(c.Id) AS comment_count,
  p.Score,
  p.ViewCount
FROM codebase_community_template.posts p
INNER JOIN codebase_community_template.comments c ON p.Id = c.PostId
GROUP BY p.Id, p.Title, p.PostTypeId, p.Score, p.ViewCount
ORDER BY comment_count DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT p.Id,
  CASE WHEN p.PostTypeId = 1 THEN p.Title ELSE 'Answer' END AS title,
  p.PostTypeId, COUNT(c.Id) AS comment_count, p.Score, p.ViewCount
FROM codebase_community_template.posts p
INNER JOIN codebase_community_template.comments c ON p.Id = c.PostId
GROUP BY p.Id, p.Title, p.PostTypeId, p.Score, p.ViewCount
ORDER BY comment_count DESC
LIMIT 20;
```

---

### Template 22: Top Commenters
**Natural Language**: "Who are the most active commenters?"
**Domain**: Engagement Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  u.Id,
  u.DisplayName,
  COUNT(c.Id) AS comment_count
FROM codebase_community_template.users u
INNER JOIN codebase_community_template.comments c ON u.Id = c.UserId
GROUP BY u.Id, u.DisplayName
ORDER BY comment_count DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT u.Id, u.DisplayName, COUNT(c.Id) AS comment_count
FROM codebase_community_template.users u
INNER JOIN codebase_community_template.comments c ON u.Id = c.UserId
GROUP BY u.Id, u.DisplayName
ORDER BY comment_count DESC
LIMIT 20;
```

---

### Template 23: Voting Trends
**Natural Language**: "How many votes were cast per day in the last {{days}} days?"
**Domain**: Engagement Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  CreationDate AS vote_date,
  COUNT(*) AS vote_count,
  SUM(CASE WHEN VoteTypeId = 2 THEN 1 ELSE 0 END) AS upvotes,
  SUM(CASE WHEN VoteTypeId = 3 THEN 1 ELSE 0 END) AS downvotes
FROM codebase_community_template.votes
WHERE CreationDate >= DATE_SUB(CURDATE(), INTERVAL {{days}} DAY)
GROUP BY CreationDate
ORDER BY vote_date DESC;
```

**Example**:
```sql
SELECT CreationDate AS vote_date, COUNT(*) AS vote_count,
  SUM(CASE WHEN VoteTypeId = 2 THEN 1 ELSE 0 END) AS upvotes,
  SUM(CASE WHEN VoteTypeId = 3 THEN 1 ELSE 0 END) AS downvotes
FROM codebase_community_template.votes
WHERE CreationDate >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
GROUP BY CreationDate
ORDER BY vote_date DESC;
```

---

### Template 24: Post Vote Distribution
**Natural Language**: "What is the vote distribution for post {{post_id}}?"
**Domain**: Engagement Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  VoteTypeId,
  COUNT(*) AS vote_count
FROM codebase_community_template.votes
WHERE PostId = {{post_id}}
GROUP BY VoteTypeId
ORDER BY vote_count DESC;
```

**Example**:
```sql
SELECT VoteTypeId, COUNT(*) AS vote_count
FROM codebase_community_template.votes
WHERE PostId = 1
GROUP BY VoteTypeId
ORDER BY vote_count DESC;
```

---

### Template 25: Most Voted Posts
**Natural Language**: "What posts have received the most votes?"
**Domain**: Engagement Analytics
**Complexity**: Medium

**SQL Template**:
```sql
SELECT
  p.Id,
  CASE WHEN p.PostTypeId = 1 THEN p.Title ELSE 'Answer' END AS title,
  p.PostTypeId,
  COUNT(v.Id) AS vote_count,
  SUM(CASE WHEN v.VoteTypeId = 2 THEN 1 ELSE 0 END) AS upvotes,
  SUM(CASE WHEN v.VoteTypeId = 3 THEN 1 ELSE 0 END) AS downvotes,
  p.Score
FROM codebase_community_template.posts p
INNER JOIN codebase_community_template.votes v ON p.Id = v.PostId
GROUP BY p.Id, p.Title, p.PostTypeId, p.Score
ORDER BY vote_count DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT p.Id,
  CASE WHEN p.PostTypeId = 1 THEN p.Title ELSE 'Answer' END AS title,
  p.PostTypeId, COUNT(v.Id) AS vote_count,
  SUM(CASE WHEN v.VoteTypeId = 2 THEN 1 ELSE 0 END) AS upvotes,
  SUM(CASE WHEN v.VoteTypeId = 3 THEN 1 ELSE 0 END) AS downvotes, p.Score
FROM codebase_community_template.posts p
INNER JOIN codebase_community_template.votes v ON p.Id = v.PostId
GROUP BY p.Id, p.Title, p.PostTypeId, p.Score
ORDER BY vote_count DESC
LIMIT 20;
```

---

### Template 26: User Comment Activity
**Natural Language**: "What comments has user {{user_id}} made?"
**Domain**: Engagement Analytics
**Complexity**: Medium

**SQL Template**:
```sql
SELECT
  c.Id,
  c.Text,
  c.Score,
  c.CreationDate,
  p.Id AS post_id,
  CASE WHEN p.PostTypeId = 1 THEN p.Title ELSE 'Answer' END AS post_title
FROM codebase_community_template.comments c
INNER JOIN codebase_community_template.posts p ON c.PostId = p.Id
WHERE c.UserId = {{user_id}}
ORDER BY c.CreationDate DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT c.Id, c.Text, c.Score, c.CreationDate,
  p.Id AS post_id,
  CASE WHEN p.PostTypeId = 1 THEN p.Title ELSE 'Answer' END AS post_title
FROM codebase_community_template.comments c
INNER JOIN codebase_community_template.posts p ON c.PostId = p.Id
WHERE c.UserId = 8
ORDER BY c.CreationDate DESC
LIMIT 20;
```

---

### Template 27: Comment Sentiment Analysis
**Natural Language**: "What is the score distribution of comments on post {{post_id}}?"
**Domain**: Engagement Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  Score,
  COUNT(*) AS comment_count
FROM codebase_community_template.comments
WHERE PostId = {{post_id}}
GROUP BY Score
ORDER BY Score DESC;
```

**Example**:
```sql
SELECT Score, COUNT(*) AS comment_count
FROM codebase_community_template.comments
WHERE PostId = 1
GROUP BY Score
ORDER BY Score DESC;
```

---

### Template 28: Recent Activity on Post
**Natural Language**: "What is the recent activity (comments and votes) on post {{post_id}}?"
**Domain**: Engagement Analytics
**Complexity**: Complex

**SQL Template**:
```sql
SELECT
  'comment' AS activity_type,
  c.Id,
  c.CreationDate,
  c.Score,
  u.DisplayName AS user_name,
  c.Text
FROM codebase_community_template.comments c
INNER JOIN codebase_community_template.users u ON c.UserId = u.Id
WHERE c.PostId = {{post_id}}

UNION ALL

SELECT
  'vote' AS activity_type,
  v.Id,
  v.CreationDate,
  CASE WHEN v.VoteTypeId = 2 THEN 1 ELSE -1 END AS Score,
  u.DisplayName AS user_name,
  CAST(v.VoteTypeId AS CHAR) AS Text
FROM codebase_community_template.votes v
INNER JOIN codebase_community_template.users u ON v.UserId = u.Id
WHERE v.PostId = {{post_id}}

ORDER BY CreationDate DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT 'comment' AS activity_type, c.Id, c.CreationDate, c.Score,
  u.DisplayName AS user_name, c.Text
FROM codebase_community_template.comments c
INNER JOIN codebase_community_template.users u ON c.UserId = u.Id
WHERE c.PostId = 1

UNION ALL

SELECT 'vote' AS activity_type, v.Id, v.CreationDate,
  CASE WHEN v.VoteTypeId = 2 THEN 1 ELSE -1 END AS Score,
  u.DisplayName AS user_name, CAST(v.VoteTypeId AS CHAR) AS Text
FROM codebase_community_template.votes v
INNER JOIN codebase_community_template.users u ON v.UserId = u.Id
WHERE v.PostId = 1

ORDER BY CreationDate DESC
LIMIT 50;
```

---

### Template 29: Engagement Rate by User
**Natural Language**: "What is the engagement rate (comments + votes per post) for user {{user_id}}?"
**Domain**: Engagement Analytics
**Complexity**: Medium

**SQL Template**:
```sql
SELECT
  u.DisplayName,
  COUNT(DISTINCT p.Id) AS post_count,
  COUNT(DISTINCT c.Id) AS comments_received,
  COUNT(DISTINCT v.Id) AS votes_received,
  ROUND(COUNT(DISTINCT c.Id) * 1.0 / NULLIF(COUNT(DISTINCT p.Id), 0), 2) AS avg_comments_per_post,
  ROUND(COUNT(DISTINCT v.Id) * 1.0 / NULLIF(COUNT(DISTINCT p.Id), 0), 2) AS avg_votes_per_post
FROM codebase_community_template.users u
INNER JOIN codebase_community_template.posts p ON u.Id = p.OwnerUserId
LEFT JOIN codebase_community_template.comments c ON p.Id = c.PostId
LEFT JOIN codebase_community_template.votes v ON p.Id = v.PostId
WHERE u.Id = {{user_id}}
GROUP BY u.DisplayName;
```

**Example**:
```sql
SELECT u.DisplayName,
  COUNT(DISTINCT p.Id) AS post_count,
  COUNT(DISTINCT c.Id) AS comments_received,
  COUNT(DISTINCT v.Id) AS votes_received,
  ROUND(COUNT(DISTINCT c.Id) * 1.0 / NULLIF(COUNT(DISTINCT p.Id), 0), 2) AS avg_comments_per_post,
  ROUND(COUNT(DISTINCT v.Id) * 1.0 / NULLIF(COUNT(DISTINCT p.Id), 0), 2) AS avg_votes_per_post
FROM codebase_community_template.users u
INNER JOIN codebase_community_template.posts p ON u.Id = p.OwnerUserId
LEFT JOIN codebase_community_template.comments c ON p.Id = c.PostId
LEFT JOIN codebase_community_template.votes v ON p.Id = v.PostId
WHERE u.Id = 8
GROUP BY u.DisplayName;
```

---

### Template 30: Most Active Voters
**Natural Language**: "Who are the most active voters?"
**Domain**: Engagement Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  u.Id,
  u.DisplayName,
  COUNT(v.Id) AS vote_count,
  SUM(CASE WHEN v.VoteTypeId = 2 THEN 1 ELSE 0 END) AS upvotes_cast,
  SUM(CASE WHEN v.VoteTypeId = 3 THEN 1 ELSE 0 END) AS downvotes_cast
FROM codebase_community_template.users u
INNER JOIN codebase_community_template.votes v ON u.Id = v.UserId
GROUP BY u.Id, u.DisplayName
ORDER BY vote_count DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT u.Id, u.DisplayName, COUNT(v.Id) AS vote_count,
  SUM(CASE WHEN v.VoteTypeId = 2 THEN 1 ELSE 0 END) AS upvotes_cast,
  SUM(CASE WHEN v.VoteTypeId = 3 THEN 1 ELSE 0 END) AS downvotes_cast
FROM codebase_community_template.users u
INNER JOIN codebase_community_template.votes v ON u.Id = v.UserId
GROUP BY u.Id, u.DisplayName
ORDER BY vote_count DESC
LIMIT 20;
```

---

## TAG ANALYTICS TEMPLATES (10 questions)

### Template 31: Tag Usage Statistics
**Natural Language**: "What are the most popular tags?"
**Domain**: Tag Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  TagName,
  Count AS usage_count,
  ROUND(Count * 100.0 / (SELECT SUM(Count) FROM codebase_community_template.tags), 2) AS percentage
FROM codebase_community_template.tags
ORDER BY Count DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT TagName, Count AS usage_count,
  ROUND(Count * 100.0 / (SELECT SUM(Count) FROM codebase_community_template.tags), 2) AS percentage
FROM codebase_community_template.tags
ORDER BY Count DESC
LIMIT 20;
```

---

### Template 32: Questions by Multiple Tags
**Natural Language**: "What questions have both {{tag1}} and {{tag2}}?"
**Domain**: Tag Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  Id,
  Title,
  Tags,
  Score,
  AnswerCount,
  ViewCount,
  CreaionDate
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND Tags LIKE '%<{{tag1}}>%'
  AND Tags LIKE '%<{{tag2}}>%'
ORDER BY Score DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT Id, Title, Tags, Score, AnswerCount, ViewCount, CreaionDate
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND Tags LIKE '%<python>%'
  AND Tags LIKE '%<pandas>%'
ORDER BY Score DESC
LIMIT 20;
```

---

### Template 33: Tag Expertise Leaders
**Natural Language**: "Who are the top experts for {{tag}}?"
**Domain**: Tag Analytics
**Complexity**: Medium

**SQL Template**:
```sql
WITH tag_experts AS (
  SELECT
    a.OwnerUserId,
    COUNT(*) AS answer_count,
    SUM(a.Score) AS total_score,
    AVG(a.Score) AS avg_score
  FROM codebase_community_template.posts a
  INNER JOIN codebase_community_template.posts q ON a.ParentId = q.Id
  WHERE a.PostTypeId = 2  -- Answers
    AND q.PostTypeId = 1  -- Questions
    AND q.Tags LIKE '%<{{tag}}>%'
    AND a.OwnerUserId IS NOT NULL
  GROUP BY a.OwnerUserId
  HAVING answer_count >= {{min_answers}}
)
SELECT
  u.DisplayName,
  te.answer_count,
  te.total_score,
  ROUND(te.avg_score, 2) AS avg_score_per_answer
FROM tag_experts te
INNER JOIN codebase_community_template.users u ON te.OwnerUserId = u.Id
ORDER BY total_score DESC
LIMIT {{N}};
```

**Example**:
```sql
WITH tag_experts AS (
  SELECT
    a.OwnerUserId,
    COUNT(*) AS answer_count,
    SUM(a.Score) AS total_score,
    AVG(a.Score) AS avg_score
  FROM codebase_community_template.posts a
  INNER JOIN codebase_community_template.posts q ON a.ParentId = q.Id
  WHERE a.PostTypeId = 2 AND q.PostTypeId = 1
    AND q.Tags LIKE '%<r>%'
    AND a.OwnerUserId IS NOT NULL
  GROUP BY a.OwnerUserId
  HAVING answer_count >= 5
)
SELECT u.DisplayName, te.answer_count, te.total_score,
  ROUND(te.avg_score, 2) AS avg_score_per_answer
FROM tag_experts te
INNER JOIN codebase_community_template.users u ON te.OwnerUserId = u.Id
ORDER BY total_score DESC
LIMIT 10;
```

---

### Template 34: Unanswered Questions by Tag
**Natural Language**: "What tags have the highest percentage of unanswered questions?"
**Domain**: Tag Analytics
**Complexity**: Complex

**SQL Template**:
```sql
WITH tag_unanswered AS (
  SELECT
    SUBSTRING_INDEX(SUBSTRING_INDEX(Tags, '><', n.n), '>', -1) AS tag_name,
    COUNT(*) AS total_questions,
    SUM(CASE WHEN AnswerCount = 0 THEN 1 ELSE 0 END) AS unanswered_count
  FROM codebase_community_template.posts p
  CROSS JOIN (
    SELECT 1 AS n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL
    SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL
    SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10
  ) n
  WHERE p.PostTypeId = 1
    AND p.Tags LIKE '<%>'
    AND n.n <= LENGTH(p.Tags) - LENGTH(REPLACE(p.Tags, '><', '')) + 1
  GROUP BY tag_name
  HAVING total_questions >= {{min_questions}}
)
SELECT
  tag_name,
  total_questions,
  unanswered_count,
  ROUND(unanswered_count * 100.0 / total_questions, 2) AS unanswered_percentage
FROM tag_unanswered
ORDER BY unanswered_percentage DESC
LIMIT {{N}};
```

**Example**:
```sql
WITH tag_unanswered AS (
  SELECT
    SUBSTRING_INDEX(SUBSTRING_INDEX(Tags, '><', n.n), '>', -1) AS tag_name,
    COUNT(*) AS total_questions,
    SUM(CASE WHEN AnswerCount = 0 THEN 1 ELSE 0 END) AS unanswered_count
  FROM codebase_community_template.posts p
  CROSS JOIN (
    SELECT 1 AS n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL
    SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL
    SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10
  ) n
  WHERE p.PostTypeId = 1 AND p.Tags LIKE '<%>'
    AND n.n <= LENGTH(p.Tags) - LENGTH(REPLACE(p.Tags, '><', '')) + 1
  GROUP BY tag_name
  HAVING total_questions >= 10
)
SELECT
  tag_name,
  total_questions,
  unanswered_count,
  ROUND(unanswered_count * 100.0 / total_questions, 2) AS unanswered_percentage
FROM tag_unanswered
ORDER BY unanswered_percentage DESC
LIMIT 20;
```

---

### Template 35: Tag Growth Trend
**Natural Language**: "How has {{tag}} usage changed over the last {{months}} months?"
**Domain**: Tag Analytics
**Complexity**: Medium

**SQL Template**:
```sql
SELECT
  DATE_FORMAT(CreaionDate, '%Y-%m') AS month,
  COUNT(*) AS question_count
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND Tags LIKE '%<{{tag}}>%'
  AND CreaionDate >= DATE_SUB(CURDATE(), INTERVAL {{months}} MONTH)
GROUP BY DATE_FORMAT(CreaionDate, '%Y-%m')
ORDER BY month;
```

**Example**:
```sql
SELECT DATE_FORMAT(CreaionDate, '%Y-%m') AS month, COUNT(*) AS question_count
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND Tags LIKE '%<python>%'
  AND CreaionDate >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
GROUP BY DATE_FORMAT(CreaionDate, '%Y-%m')
ORDER BY month;
```

---

### Template 36: Related Tags
**Natural Language**: "What tags are commonly used together with {{tag}}?"
**Domain**: Tag Analytics
**Complexity**: Complex

**SQL Template**:
```sql
WITH tag_combinations AS (
  SELECT
    SUBSTRING_INDEX(SUBSTRING_INDEX(Tags, '><', n.n), '>', -1) AS tag_name
  FROM codebase_community_template.posts
  CROSS JOIN (
    SELECT 1 AS n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL
    SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL
    SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10
  ) n
  WHERE PostTypeId = 1
    AND Tags LIKE '%<{{tag}}>%'
    AND Tags LIKE '<%>'
    AND n.n <= LENGTH(Tags) - LENGTH(REPLACE(Tags, '><', '')) + 1
    AND SUBSTRING_INDEX(SUBSTRING_INDEX(Tags, '><', n.n), '>', -1) != '{{tag}}'
)
SELECT
  tag_name,
  COUNT(*) AS co_occurrence_count
FROM tag_combinations
WHERE tag_name IS NOT NULL
GROUP BY tag_name
ORDER BY co_occurrence_count DESC
LIMIT {{N}};
```

**Example**:
```sql
WITH tag_combinations AS (
  SELECT
    SUBSTRING_INDEX(SUBSTRING_INDEX(Tags, '><', n.n), '>', -1) AS tag_name
  FROM codebase_community_template.posts
  CROSS JOIN (
    SELECT 1 AS n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL
    SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL
    SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10
  ) n
  WHERE PostTypeId = 1
    AND Tags LIKE '%<python>%'
    AND Tags LIKE '<%>'
    AND n.n <= LENGTH(Tags) - LENGTH(REPLACE(Tags, '><', '')) + 1
    AND SUBSTRING_INDEX(SUBSTRING_INDEX(Tags, '><', n.n), '>', -1) != 'python'
)
SELECT tag_name, COUNT(*) AS co_occurrence_count
FROM tag_combinations
WHERE tag_name IS NOT NULL
GROUP BY tag_name
ORDER BY co_occurrence_count DESC
LIMIT 15;
```

---

### Template 37: Tag Difficulty
**Natural Language**: "What is the average answer count for questions tagged with {{tag}}?"
**Domain**: Tag Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  ROUND(AVG(AnswerCount), 2) AS avg_answers,
  MIN(AnswerCount) AS min_answers,
  MAX(AnswerCount) AS max_answers,
  COUNT(*) AS total_questions,
  SUM(CASE WHEN AnswerCount = 0 THEN 1 ELSE 0 END) AS unanswered_count
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND Tags LIKE '%<{{tag}}>%';
```

**Example**:
```sql
SELECT ROUND(AVG(AnswerCount), 2) AS avg_answers,
  MIN(AnswerCount) AS min_answers, MAX(AnswerCount) AS max_answers,
  COUNT(*) AS total_questions,
  SUM(CASE WHEN AnswerCount = 0 THEN 1 ELSE 0 END) AS unanswered_count
FROM codebase_community_template.posts
WHERE PostTypeId = 1 AND Tags LIKE '%<machine-learning>%';
```

---

### Template 38: New Tags
**Natural Language**: "What are the newest tags created?"
**Domain**: Tag Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  t.TagName,
  t.Count AS usage_count,
  MIN(p.CreaionDate) AS first_used,
  MAX(p.CreaionDate) AS last_used
FROM codebase_community_template.tags t
INNER JOIN codebase_community_template.posts p ON p.Tags LIKE CONCAT('%<', t.TagName, '>%')
WHERE p.PostTypeId = 1
GROUP BY t.TagName, t.Count
HAVING first_used >= DATE_SUB(CURDATE(), INTERVAL {{days}} DAY)
ORDER BY first_used DESC
LIMIT {{N}};
```

**Example**:
```sql
SELECT t.TagName, t.Count AS usage_count,
  MIN(p.CreaionDate) AS first_used,
  MAX(p.CreaionDate) AS last_used
FROM codebase_community_template.tags t
INNER JOIN codebase_community_template.posts p ON p.Tags LIKE CONCAT('%<', t.TagName, '>%')
WHERE p.PostTypeId = 1
GROUP BY t.TagName, t.Count
HAVING first_used >= DATE_SUB(CURDATE(), INTERVAL 90 DAY)
ORDER BY first_used DESC
LIMIT 20;
```

---

### Template 39: Tag Wiki Information
**Natural Language**: "What is the wiki information for tag {{tag}}?"
**Domain**: Tag Analytics
**Complexity**: Medium

**SQL Template**:
```sql
SELECT
  t.TagName,
  t.Count AS usage_count,
  t.ExcerptPostId,
  t.WikiPostId,
  e.Title AS excerpt_title,
  e.Body AS excerpt_body,
  w.Title AS wiki_title,
  w.Body AS wiki_body
FROM codebase_community_template.tags t
LEFT JOIN codebase_community_template.posts e ON t.ExcerptPostId = e.Id
LEFT JOIN codebase_community_template.posts w ON t.WikiPostId = w.Id
WHERE t.TagName = '{{tag}}';
```

**Example**:
```sql
SELECT t.TagName, t.Count AS usage_count, t.ExcerptPostId, t.WikiPostId,
  e.Title AS excerpt_title, e.Body AS excerpt_body,
  w.Title AS wiki_title, w.Body AS wiki_body
FROM codebase_community_template.tags t
LEFT JOIN codebase_community_template.posts e ON t.ExcerptPostId = e.Id
LEFT JOIN codebase_community_template.posts w ON t.WikiPostId = w.Id
WHERE t.TagName = 'bayesian';
```

---

### Template 40: Tag Network Analysis
**Natural Language**: "What is the question overlap between {{tag1}} and {{tag2}}?"
**Domain**: Tag Analytics
**Complexity**: Simple

**SQL Template**:
```sql
SELECT
  COUNT(*) AS questions_with_both_tags,
  ROUND(COUNT(*) * 100.0 / (
    SELECT COUNT(*) FROM codebase_community_template.posts
    WHERE PostTypeId = 1 AND (Tags LIKE '%<{{tag1}}>%' OR Tags LIKE '%<{{tag2}}>%')
  ), 2) AS overlap_percentage
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND Tags LIKE '%<{{tag1}}>%'
  AND Tags LIKE '%<{{tag2}}>%';
```

**Example**:
```sql
SELECT COUNT(*) AS questions_with_both_tags,
  ROUND(COUNT(*) * 100.0 / (
    SELECT COUNT(*) FROM codebase_community_template.posts
    WHERE PostTypeId = 1 AND (Tags LIKE '%<python>%' OR Tags LIKE '%<r>%')
  ), 2) AS overlap_percentage
FROM codebase_community_template.posts
WHERE PostTypeId = 1
  AND Tags LIKE '%<python>%'
  AND Tags LIKE '%<r>%';
```

---

## Summary

This document provides 40 comprehensive question templates covering:
- **10 User Analytics templates**: User reputation, activity, badges, voting behavior
- **10 Content Analytics templates**: Questions, answers, views, edits, quality
- **10 Engagement Analytics templates**: Comments, votes, interaction patterns
- **10 Tag Analytics templates**: Tag popularity, expertise, trends, relationships

Each template is production-ready with natural language mappings, parameterized SQL, and concrete examples.
