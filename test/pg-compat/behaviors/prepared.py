"""Driver-agnostic behavior: a parameterized statement, reused many times,
keeps working across ProxySQL's connection multiplexing.

psycopg3 auto-prepares a statement (turning it into a real extended-protocol
Parse/Bind/Execute sequence, not just a client-side text substitution) after
it has been executed more than ``prepare_threshold`` times (default 5) on
the same connection -- see psycopg's ``prepared.py``. Looping 50 times here
guarantees the driver crosses that threshold, so the back half of this loop
genuinely exercises real server-side prepared statements multiplexed by
ProxySQL, not merely simple-protocol round trips.

Placeholder syntax note (a real adaptation, not a style choice): the brief
wrote the query with raw PostgreSQL positional placeholders (``$1``, ``$2``).
That is NOT what psycopg3's ``cursor.execute(sql, params)`` expects on the
client side -- psycopg (2 and 3 alike) uses ``%s`` placeholders in the SQL
text it is given and translates them to ``$1``/``$2``/... itself when it
builds the wire-protocol Bind message. Passing ``$1``/``$2`` literally
through ``execute()`` makes psycopg count zero ``%s`` placeholders in the
query while two params were supplied, raising
``psycopg.ProgrammingError: the query has 0 placeholders but 2 parameters
were passed`` (reproduced against this exact behavior before this fix). The
query text below therefore uses ``%s``; the actual wire protocol PostgreSQL
sees (and what ProxySQL multiplexes) still uses ``$1``/``$2`` -- that
translation is exactly what the driver is for.
"""


def run(Adapter):
    a = Adapter()
    try:
        for i in range(50):
            r = a.exec_params("SELECT %s::int + %s::int", (i, 1))
            assert r[0][0] == i + 1
    finally:
        a.close()
