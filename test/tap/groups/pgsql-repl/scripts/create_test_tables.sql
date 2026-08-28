\set ON_ERROR_STOP on

DROP DATABASE IF EXISTS sysbench;
CREATE DATABASE sysbench;

\connect sysbench;

CREATE TABLE sbtest1 (
	id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
	k integer DEFAULT 0 NOT NULL,
	c character(120) DEFAULT ''::bpchar NOT NULL,
	pad character(60) DEFAULT ''::bpchar NOT NULL
);
