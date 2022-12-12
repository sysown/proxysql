## Compilation

This folder should contain folders which tests require special dependencies for being build. Every folder
should define its own variables in which it expect to find the required dependencies for building the tests.
This path shall always be based on `$TEST_DEPS` environmental variable.

In addition, all folders should include a `README.md` detailing the variables they are defining, the path such
variables expect to find the required dependency, and the command they expect to issue in the target location.

If the dependencies are not found, compilation should issue a warning, and continue without failing. See
`deprecate_eof_support` as an example of this behavior.

## Execution

The execution from all the tests defined in this folders should be identical to the execution of tests in
the general `tests` folder.
