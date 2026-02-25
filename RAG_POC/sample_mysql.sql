-- Sample MySQL dataset for rag_ingest testing
-- Creates a simple posts table and inserts a few rows.

CREATE DATABASE IF NOT EXISTS rag_test;
USE rag_test;

DROP TABLE IF EXISTS posts;

CREATE TABLE posts (
  Id BIGINT NOT NULL PRIMARY KEY,
  Title VARCHAR(255) NOT NULL,
  Body TEXT NOT NULL,
  Tags VARCHAR(255) NULL,
  Score INT NOT NULL DEFAULT 0,
  CreationDate DATETIME NOT NULL,
  UpdatedAt DATETIME NULL
);

INSERT INTO posts (Id, Title, Body, Tags, Score, CreationDate, UpdatedAt) VALUES
(1, 'Hello RAG', 'This is the first test document. It contains sample text for chunking.', 'rag,test', 10, '2024-01-01 10:00:00', '2024-01-02 12:00:00'),
(2, 'Second Doc', 'A second document body. It has more text to ensure chunking works across boundaries.', 'example,docs', 5, '2024-01-03 09:30:00', '2024-01-03 11:00:00'),
(3, 'ProxySQL RAG', 'ProxySQL adds MCP and RAG support. This row is for ingestion testing.', 'proxysql,rag', 7, '2024-01-05 08:15:00', NULL),
(4, 'Short Note', 'Tiny.', 'misc', 1, '2024-01-06 13:00:00', NULL),
(5, 'Chunk Stress', 'This row contains a longer body to force multiple chunk boundaries when chunking is enabled. Repeat: This row contains a longer body to force multiple chunk boundaries when chunking is enabled.', 'long,chunk', 12, '2024-01-07 18:45:00', '2024-01-08 07:10:00'),
(6, 'Filter Candidate', 'This document should be filtered out by a high score threshold.', 'filter,test', 2, '2024-01-09 14:20:00', NULL),
(7, 'Tag Variation', 'Contains tags and mixed content for metadata pick/rename testing.', 'rag,meta,tag', 9, '2024-01-10 09:00:00', '2024-01-10 10:00:00'),
(8, 'Null Updated', 'Document with NULL UpdatedAt for null handling in source.', 'nulls', 6, '2024-01-11 16:30:00', NULL),
(9, 'High Score', 'This is a high score document for where_sql tests.', 'score,high', 20, '2024-01-12 08:00:00', '2024-01-12 09:30:00'),
(10, 'Low Score', 'Low score entry to test filters.', 'score,low', 0, '2024-01-13 12:00:00', NULL);
