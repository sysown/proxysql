### Tap Test Groups for CI runs

Tests in this folder are symlinks to tap test executables and dependent data files in `../tests`

This feature enables to create groups of tap tests
- of arbitrary choice
- in specified order
- using specific input data
- running pre-run `./pre-*.bash` scripts
- running post-run `./post-*.bash` scripts 

### Purpose

verifying rename and external dependencies issues

### Re-create

prefixed number forces ordering, to recreate use:
```
N=0; for F in $(ls -1 ../tests/*-t | sort); do ln -s $F $(printf %03d $N)_${F##*/}; ((N++)); done
```
dependent data files and folders:
```
for F in $(ls -1 ../tests/*{.json,.cnf,.csv} | sort); do ln -s $F ${F##*/}; ((N++)); done
for F in $(ls -1d ../tests/*/ | sort); do F=${F%/}; ln -s $F ${F##*/}; done
```
make a copy dependent data instead of a symlink if modification is needed

### Fails

currently these are failing
```
[2022-08-22 20:36:18] INFO     [proxysql-tester.py:732] SUMMARY: FAIL '028_reg_test_3223-restapi_return_codes-t'
[2022-08-22 20:36:18] INFO     [proxysql-tester.py:732] SUMMARY: FAIL '039_reg_test_3504-change_user-t'
[2022-08-22 20:36:18] INFO     [proxysql-tester.py:732] SUMMARY: FAIL '049_reg_test_3838-restapi_eintr-t'
[2022-08-22 20:36:18] INFO     [proxysql-tester.py:732] SUMMARY: FAIL '050_reg_test_3847_admin_lock-t'
[2022-08-22 20:36:18] INFO     [proxysql-tester.py:732] SUMMARY: FAIL '055_setparser_test-t'
[2022-08-22 20:36:18] INFO     [proxysql-tester.py:732] SUMMARY: FAIL '057_set_testing-multi-t'
[2022-08-22 20:36:18] INFO     [proxysql-tester.py:732] SUMMARY: FAIL '069_test_cluster_sync-t'
[2022-08-22 20:36:18] INFO     [proxysql-tester.py:732] SUMMARY: FAIL '082_test_mysql_query_digests_stages-t'
[2022-08-22 20:36:18] INFO     [proxysql-tester.py:732] SUMMARY: FAIL '104_test_unsupported_queries-t'
```
probable cause are missing dendent data files
