SELECT g AS aid, 1 AS bid, 0 AS abalance, repeat('x', 67) AS filler
FROM generate_series(1, 42) AS g;
