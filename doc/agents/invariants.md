# ProxySQL Product Invariants

These are contracts that ProxySQL makes to operators and clients. They are older than most of
the code that implements them. **Code must be checked against this list, not only against
itself.** A change that is internally consistent can still be wrong.

Rules for agents:

- **Do not break an invariant, weaken it, or add a new way to violate it,** even behind a flag or
  tier, without an explicit maintainer decision. That decision must be recorded in an issue and
  cited in the commit message.
- **A change that touches an invariant is a design change, not a fix.** Do not label it
  `fix(...)`. Stop and ask (see `common-mistakes.md` §19).
- **If you are unsure whether a change touches an invariant, assume it does** and say so in the
  PR description.
- Reviewers, human or bot, should check every PR against this list. **"The code is consistent
  with itself" is not a review result.**

---

## I-1. LOAD ... SERVERS TO RUNTIME always applies

*Decision: #6448.*

`LOAD MYSQL SERVERS TO RUNTIME` and `LOAD PGSQL SERVERS TO RUNTIME` install the admin tables into
runtime, as they did in v3.0.11:
- They never fail because of ProxySQL's internal state: locks, transactions, generation counters,
  snapshots, or SQLite read errors on admin tables. Such errors are logged.
- They never partially apply.
- No module or plugin can veto them, block them or reject part of them.
- Admin replies OK.
- Cluster sync never branches on a LOAD outcome.

If a plugin needs to know what was installed, it gets a notification *after* the install, and
cannot reject it.

The same principle is expected to apply to every other `LOAD ... TO RUNTIME` command. Do not add
new failure modes to any of them.

## I-2. The Stable tier is unchanged by innovative-tier work

*Decisions: #6448, #6411.*

Code written for v3.1 (`PROXYSQL31`, FFTO, TSDB) or v4.0 (`PROXYSQL40`, plugin chassis) must not
change any behaviour of a v3.0 Stable build. This covers:
- control flow, locking, error paths and failure modes;
- performance on hot paths;
- default values;
- the behaviour of dependency libraries (for example, the regex engine).

Code that only exists to serve v3.1/v4.0 features is either tier-gated, or provably inert on
Stable. "Compiled on every tier but only used by plugins" is not inert if it sits on a core path.

The reverse also holds: **a correctness fix must not be confined to v3.1+** unless the bug only
exists there.

## I-3. Plugins extend ProxySQL; they do not hold core admin operations hostage

*Decision: #6448.*

No plugin hook can:
- make a core admin command fail, block, or partially apply;
- change a core command's reply.

Plugins observe core state and add their own tables, commands and listeners. Core does not wait
on plugins to complete its own operations.

---

## Adding an invariant

Invariants are added or changed only by a maintainer. Each one needs:
- a short statement;
- the issue or decision that ratifies it;
- the bug that motivated it, if any.

An agent that thinks a contract is missing may *propose* one in the PR description, but must not
add it here itself.
