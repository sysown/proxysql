# ProxySQL Project Conventions for Agents

## Build System

```bash
make build_deps -j4    # Build dependencies (first time only)
make build_lib -j4     # Build libproxysql.a
make build_tap_tests   # Build all tests (includes unit tests)
make -j4               # Full build (deps + lib + binary)
```

Always verify `make build_lib -j4` compiles successfully before submitting changes to `lib/` or `include/`.

## Directory Layout

| Directory | Purpose | When to modify |
|-----------|---------|---------------|
| `include/` | All headers (.h/.hpp) | When adding new declarations |
| `lib/` | Core library sources → compiled into `libproxysql.a` | When adding/modifying implementations |
| `src/` | Entry point (`main.cpp`) and daemon code | Rarely — avoid unless necessary |
| `test/tap/tests/unit/` | Unit tests (no infrastructure needed) | When adding unit tests |
| `test/tap/tests/` | E2E TAP tests (need running ProxySQL + backends) | When adding integration tests |
| `test/tap/test_helpers/` | Unit test harness (`test_globals`, `test_init`) | When extending test infrastructure |
| `doc/` | Documentation | When documenting features |

## Unit Test Conventions

### File placement
- Unit tests go in `test/tap/tests/unit/`, NOT in `test/tap/tests/`
- File naming: `<descriptive_name>_unit-t.cpp` or `<descriptive_name>-t.cpp`

### Test harness (MUST use)
Every unit test MUST use the existing harness:

```cpp
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
// ... other headers for types you need

int main() {
    plan(<number_of_tests>);
    test_init_minimal();   // Always call first

    // ... test functions with ok(), is(), etc.

    test_cleanup_minimal(); // Always call last
    return exit_status();
}
```

The harness provides:
- All `Glo*` global stubs (defined in `test_globals.cpp`)
- TAP noise symbols (`noise_failures`, `stop_noise_tools`, etc.)
- Component init helpers: `test_init_auth()`, `test_init_query_cache()`, `test_init_query_processor()`
- Cleanup functions for each

### Makefile registration
Edit `test/tap/tests/unit/Makefile`:
1. Append test name to `UNIT_TESTS :=` line
2. Add build rule:
```makefile
my_test-t: my_test-t.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		$(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@
```

### What the unit test Makefile does
- Compiles `tap.o` directly from source (no `cpp-dotenv` dependency)
- Links test binary against `libproxysql.a` + `test_globals.o` + `test_init.o`
- This means tests call the REAL production functions, not copies

### Reference files
- `test/tap/tests/unit/connection_pool_unit-t.cpp` — good example of a unit test
- `test/tap/tests/unit/rule_matching_unit-t.cpp` — good example with regex testing
- `test/tap/test_helpers/test_globals.cpp` — what symbols are already stubbed
- `include/ConnectionPoolDecision.h` — good example of a standalone extracted header

## Header Conventions

### Include guards
Use `#ifndef HEADER_NAME_H` / `#define HEADER_NAME_H` / `#endif`.

### Avoiding circular dependencies
The ProxySQL include chain has circular dependencies:
```
proxysql.h → proxysql_structs.h → proxysql_glovars.hpp
cpp.h → MySQL_Thread.h → MySQL_Session.h → proxysql.h (circular)
cpp.h → MySQL_HostGroups_Manager.h → Base_HostGroups_Manager.h → proxysql.h (circular)
```

When extracting functions from tightly-coupled classes, create a **standalone header** in `include/` with its own include guard and no ProxySQL dependencies. Example: `include/ConnectionPoolDecision.h`.

### Naming
- Class headers: `PascalCase` matching the class name
- Standalone function headers: `PascalCase` describing the feature

## Git Workflow

### Branch model
- `v3.0` — main stable branch (DO NOT target PRs here for unit test work)
- `v3.0-5473` — unit test feature branch (target PRs here for test-related changes)
- Feature branches: `v3.0-<issue_number>` (e.g., `v3.0-5491`)

### Creating a feature branch
```bash
git checkout -b v3.0-<issue_number> v3.0-5473
```

### Incorporating upstream changes
Use `git rebase`, NOT `git merge`:
```bash
git fetch origin v3.0-5473
git rebase origin/v3.0-5473
# Resolve conflicts if any
git push --force-with-lease
```

### Commit messages
- Descriptive subject line (what changed and why)
- Reference issue numbers: `(#5491)`
- Separate production code changes from test changes in different commits

## Coding Conventions

- C++17 required
- Class names: `PascalCase` with protocol prefixes (`MySQL_`, `PgSQL_`, `ProxySQL_`)
- Member variables: `snake_case`
- Constants/macros: `UPPER_SNAKE_CASE`
- Doxygen documentation on all public functions: `@brief`, `@param`, `@return`
- `(char *)` casts on string literals are acceptable (codebase convention)

## Dual Protocol

ProxySQL supports both MySQL and PostgreSQL. When modifying one protocol's code, check if the same change is needed for the other:

| MySQL | PostgreSQL |
|-------|-----------|
| `MySQL_Session` | `PgSQL_Session` |
| `MySQL_Thread` | `PgSQL_Thread` |
| `MySQL_HostGroups_Manager` | `PgSQL_HostGroups_Manager` |
| `MySQL_Monitor` | `PgSQL_Monitor` |
| `MySQL_Query_Processor` | `PgSQL_Query_Processor` |
| `MySrvConnList` | `PgSQL_SrvConnList` |

Some components share a template base (`Base_Session`, `Base_HostGroups_Manager`, `Query_Processor<T>`). Changes to the template cover both protocols.
