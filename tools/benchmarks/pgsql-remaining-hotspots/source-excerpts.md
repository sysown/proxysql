# Source evidence

Checkout HEAD: `e161f4789ce3c7ee0610f2e4a7d76e4988afcf8d`. Runtime source binary: `4699f3175` (HEAD adds report artifacts only).

## lib/PgSQL_Protocol.cpp:2798

```cpp
 2798
 2799 	if (buffer) {
 2800 		free(buffer);
 2801 		buffer = NULL;
 2802 	}
 2803 }
 2804
 2805 void PgSQL_Query_Result::buffer_init() {
 2806 	if (buffer == NULL) {
 2807 		buffer = (unsigned char*)malloc(PGSQL_RESULTSET_BUFLEN);
 2808 	}
 2809 	buffer_used = 0;
 2810 }
 2811
 2812 void PgSQL_Query_Result::init(PgSQL_Protocol* _proto, PgSQL_Data_Stream* _myds, PgSQL_Connection* _conn) {
 2813 	PROXY_TRACE2();
 2814 	proto = _proto;
 2815 	conn = _conn;
 2816 	myds = _myds;
 2817
 2818 	if (conn->processing_multi_statement == false)
 2819 		transfer_started = false;
 2820 	clear();
 2821
 2822 	if (proto == NULL) {
 2823 		return; // this is a mirror
 2824 	}
 2825 }
```

## lib/PgSQL_Protocol.cpp:3062

```cpp
 3062 	case 'c': // CopyDone: no side effect; CommandComplete follows
 3063 		break;
 3064 	case 'Z': // ReadyForQuery: final message; records txn status and finalizes buffer.
 3065 		if (conn && payload_len >= 1) {
 3066 			conn->set_ready_for_query_status((char)payload[0]);
 3067 		}
 3068 		result_packet_type |= PGSQL_QUERY_RESULT_READY;
 3069 		stmt_had_tuple = false;
 3070 		// Mirror add_ready_status(): flush the in-line buffer into PSarrayOUT so the
 3071 		// completed result is wholly in PSarrayOUT (get_resultset asserts buffer_used==0).
 3072 		buffer_to_PSarrayOut();
 3073 		// NOTE: the session's PgSQL_ExplicitTxnStateMgr (BEGIN/COMMIT/ROLLBACK/
 3074 		// SAVEPOINT state) is fed EXACTLY ONCE per query by PgSQL_Session::handler()'s
```

## lib/PgSQL_Protocol.cpp:3119

```cpp
 3119 void PgSQL_Query_Result::buffer_to_PSarrayOut() {
 3120 	if (buffer_used == 0)
 3121 		return;	// exit immediately if the buffer is empty
 3122 	if (buffer_used < PGSQL_RESULTSET_BUFLEN / 2) {
 3123 		buffer = (unsigned char*)realloc(buffer, buffer_used);
 3124 	}
 3125 	PSarrayOUT.add(buffer, buffer_used);
 3126 	buffer = (unsigned char*)malloc(PGSQL_RESULTSET_BUFLEN);
 3127 	buffer_used = 0;
 3128 }
 3129
```

## lib/PgSQL_Connection.cpp:5593

```cpp
 5593 void PgSQL_Connection::ProcessQueryAndSetStatusFlags(const char* query_digest_text, int savepoint_count) {
 5594 	if (query_digest_text == NULL) return;
 5595 	// unknown what to do with multiplex
 5596 	int mul = -1;
 5597 	if (myds) {
 5598 		if (myds->sess) {
 5599 			if (myds->sess->qpo) {
 5600 				mul = myds->sess->qpo->multiplex;
 5601 				if (mul == 0) {
 5602 					set_status(true, STATUS_PGSQL_CONNECTION_NO_MULTIPLEX);
 5603 				} else {
 5604 					if (mul == 1) {
 5605 						set_status(false, STATUS_PGSQL_CONNECTION_NO_MULTIPLEX);
 5606 					}
 5607 				}
 5608 			}
 5609 		}
 5610 	}
 5611
 5612 	if (get_status(STATUS_PGSQL_CONNECTION_USER_VARIABLE) == false) { // we search for variables only if not already set
 5613 		if (strncasecmp(query_digest_text, "SET ", 4) == 0) {
 5614 			// For issue #555 , multiplexing is disabled if --safe-updates is used (see session_vars definition)
 5615 			int sqloh = pgsql_thread___set_query_lock_on_hostgroup;
 5616 			switch (sqloh) {
 5617 			case 0: // old algorithm
 5618 				if (mul != 2) {
 5619 					if (index(query_digest_text, '.')) { // mul = 2 has a special meaning : do not disable multiplex for variables in THIS QUERY ONLY
 5620 						if (!IsKeepMultiplexEnabledVariables(query_digest_text)) {
 5621 							set_status(true, STATUS_PGSQL_CONNECTION_USER_VARIABLE);
 5622 						}
 5623 					}
 5624 				}
 5625 				break;
 5626 			case 1: // new algorithm
 5627 				if (myds->sess->locked_on_hostgroup > -1) {
 5628 					// locked_on_hostgroup was set, so some variable wasn't parsed
 5629 					set_status(true, STATUS_PGSQL_CONNECTION_USER_VARIABLE);
 5630 				}
 5631 				break;
 5632 			default:
 5633 				break;
 5634 			}
 5635 		} else {
 5636 			if (mul != 2 && index(query_digest_text, '.')) { // mul = 2 has a special meaning : do not disable multiplex for variables in THIS QUERY ONLY
 5637 				if (!IsKeepMultiplexEnabledVariables(query_digest_text)) {
 5638 					set_status(true, STATUS_PGSQL_CONNECTION_USER_VARIABLE);
 5639 				}
 5640 			}
 5641 		}
 5642 	}
 5643 	if (get_status(STATUS_PGSQL_CONNECTION_PREPARED_STATEMENT) == false) { // we search if prepared was already executed
 5644 		if (!strncasecmp(query_digest_text, "PREPARE ", strlen("PREPARE "))) {
 5645 			set_status(true, STATUS_PGSQL_CONNECTION_PREPARED_STATEMENT);
 5646 		}
 5647 	}
 5648
 5649 	// CREATE TEMP TABLE creates a session-scoped temporary table.
 5650 	// It exists only for the duration of the session and is automatically dropped when the session ends.
 5651 	// Since we are not tracking individual temp tables, the status will be reset only on DISCARD TEMP.
 5652 	if (get_status(STATUS_PGSQL_CONNECTION_TEMPORARY_TABLE) == false) { // we search for temporary if not already set
 5653 		if (!strncasecmp(query_digest_text, "CREATE TEMPORARY TABLE ", strlen("CREATE TEMPORARY TABLE ")) ||
 5654 			!strncasecmp(query_digest_text, "CREATE TEMP TABLE ", strlen("CREATE TEMP TABLE "))) {
 5655 			set_status(true, STATUS_PGSQL_CONNECTION_TEMPORARY_TABLE);
 5656 		}
 5657 	} else { // we search for temporary if not already set
 5658 		if (!strncasecmp(query_digest_text, "DISCARD TEMP", strlen("DISCARD TEMP"))) {
 5659 			set_status(false, STATUS_PGSQL_CONNECTION_TEMPORARY_TABLE);
 5660 		}
 5661 	}
 5662
 5663 	// LOCK TABLE is transaction-scoped:
 5664 	// The lock is released automatically when the transaction ends
 5665 	// (either COMMIT or ROLLBACK). It cannot persist beyond the transaction.
 5666 	if (get_status(STATUS_PGSQL_CONNECTION_LOCK_TABLES) == false) { // we search for lock tables only if not already set
 5667 		if (IsKnownActiveTransaction() == true &&
 5668 			!strncasecmp(query_digest_text, "LOCK TABLE", strlen("LOCK TABLE"))) {
 5669 			set_status(true, STATUS_PGSQL_CONNECTION_LOCK_TABLES);
 5670 		}
 5671 	} else {
 5672 		if (IsKnownActiveTransaction() == false) {
 5673 			set_status(false, STATUS_PGSQL_CONNECTION_LOCK_TABLES);
 5674 		}
 5675 	}
 5676
 5677 	// pg_advisory_xact_lock is transaction-scoped:
 5678 	// The advisory lock is automatically released at the end of the current transaction
 5679 	// (either COMMIT or ROLLBACK). It does not persist beyond the transaction.
 5680 	if (get_status(STATUS_PGSQL_CONNECTION_ADVISORY_XACT_LOCK) == false) {
 5681 		if (IsKnownActiveTransaction() == true &&
 5682 			!strncasecmp(query_digest_text, "SELECT pg_advisory_xact_lock", sizeof("SELECT pg_advisory_xact_lock") - 1)) {
 5683 			set_status(true, STATUS_PGSQL_CONNECTION_ADVISORY_XACT_LOCK);
 5684 		}
 5685 	} else {
 5686 		if (IsKnownActiveTransaction() == false) {
 5687 			set_status(false, STATUS_PGSQL_CONNECTION_ADVISORY_XACT_LOCK);
 5688 		}
 5689 	}
 5690
 5691 	// pg_advisory_lock is session-level:
 5692 	// In ProxySQL, as we are not tracking individual Advisory Locks, we will reset the status only
 5693 	// when we see pg_advisory_unlock_all, which releases all session-level advisory locks.
 5694 	if (get_status(STATUS_PGSQL_CONNECTION_ADVISORY_LOCK) == false) { // we search for pg_advisory_lock* if not already set
 5695 		if (!strncasecmp(query_digest_text, "SELECT pg_advisory_lock", sizeof("SELECT pg_advisory_lock")-1)) {
 5696 			set_status(true, STATUS_PGSQL_CONNECTION_ADVISORY_LOCK);
 5697 		}
 5698 	} else {
 5699 		if (!strncasecmp(query_digest_text, "SELECT pg_advisory_unlock_all", sizeof("SELECT pg_advisory_unlock_all") - 1)) {
 5700 			set_status(false, STATUS_PGSQL_CONNECTION_ADVISORY_LOCK);
 5701 		}
 5702 	}
 5703
 5704 	update_listen_status(query_digest_text);
 5705
 5706 	// A WITH HOLD cursor survives COMMIT on the backend connection; pooled, the next client
 5707 	// could FETCH this client's rows from it. Cursors are not tracked one by one, so only
 5708 	// CLOSE ALL clears the flag (DISCARD ALL clears it through reset()). With
 5709 	// query_digests_keep_comment the digest can start with a comment, so it is skipped first.
 5710 	const char* first_stmt = pgsql_stmt_skip_lead(query_digest_text, NULL);
 5711 	if (get_status(STATUS_PGSQL_CONNECTION_HOLD_CURSOR) == false) {
 5712 		// ';': a multi-statement query whose DECLARE is not the first statement
 5713 		if ((pgsql_stmt_first_keyword_is(first_stmt, "DECLARE") || strchr(query_digest_text, ';')) &&
 5714 			strcasestr(query_digest_text, "CURSOR WITH HOLD")) {
 5715 			set_status(true, STATUS_PGSQL_CONNECTION_HOLD_CURSOR);
 5716 		}
 5717 	} else {
 5718 		if (pgsql_stmt_first_keyword_is(first_stmt, "CLOSE ALL")) {
 5719 			set_status(false, STATUS_PGSQL_CONNECTION_HOLD_CURSOR);
 5720 		}
 5721 	}
 5722
 5723 	// CREATE SEQUENCE vs CREATE TEMP SEQUENCE:
 5724 	/// - CREATE SEQUENCE: Persistent; survives across sessions until explicitly dropped.
 5725 	// - CREATE TEMP SEQUENCE: Session-scoped; automatically dropped when the session ends.
 5726 	// Since we are not tracking individual sequences, the status will not be reset on DROP SEQUENCE.
 5727 	// Instead, it will be reset on DISCARD SEQUENCES, which removes all session-scoped sequences.
 5728 	if (get_status(STATUS_PGSQL_CONNECTION_HAS_SEQUENCES) == false) { // we search for sequences only if not already set
 5729 		if (!strncasecmp(query_digest_text, "CREATE ", sizeof("CREATE ") - 1) &&
 5730 			(!strncasecmp(query_digest_text + sizeof("CREATE ") - 1, "SEQUENCE", sizeof("SEQUENCE") - 1) ||
 5731 				!strncasecmp(query_digest_text + sizeof("CREATE ") - 1, "TEMP SEQUENCE", sizeof("TEMP SEQUENCE") - 1) ||
 5732 				!strncasecmp(query_digest_text + sizeof("CREATE ") - 1, "TEMPORARY SEQUENCE", sizeof("TEMPORARY SEQUENCE") - 1))) {
 5733 			set_status(true, STATUS_PGSQL_CONNECTION_HAS_SEQUENCES);
 5734 		}
 5735 	} else { // we search for sequences only if not already set
 5736 		if (!strncasecmp(query_digest_text, "DISCARD SEQUENCES", sizeof("DISCARD SEQUENCES")-1)) {
 5737 			set_status(false, STATUS_PGSQL_CONNECTION_HAS_SEQUENCES);
 5738 		}
 5739 	}
 5740
 5741 	// SAVEPOINT is transaction-scoped:
 5742 	// The savepoint is automatically released at the end of the current transaction
 5743 	// (either COMMIT or ROLLBACK). It does not persist beyond the transaction.
 5744 	// If the savepoint count is -1, it means we are not sure if we are in a transaction or not.
 5745 	// If the savepoint count is > 0, it means we are in a transaction and have savepoints.
 5746 	// If the savepoint count is 0, it means we are not in a transaction and have no savepoints.
 5747 	if (get_status(STATUS_PGSQL_CONNECTION_HAS_SAVEPOINT) == false) {
 5748 		if (savepoint_count > 0) {
 5749 			set_status(true, STATUS_PGSQL_CONNECTION_HAS_SAVEPOINT);
 5750 		} else if (savepoint_count == -1) {
```

## lib/PgSQL_Connection.cpp:6320

```cpp
 6320 	if (!query_result_reuse) {
 6321 		if (query_result) {
 6322 #ifdef DEBUG
 6323 			assert(!query_result);
 6324 #endif
 6325 			delete query_result;
 6326 			query_result = nullptr;
 6327 		}
 6328 		query_result = new PgSQL_Query_Result();
 6329 	} else {
 6330 		query_result = query_result_reuse;
 6331 		query_result_reuse = nullptr;
 6332 	}
 6333
 6334 	if (myds->sess->mirror == false) {
 6335 		query_result->init(&myds->sess->client_myds->myprot, myds, this);
 6336 	}
 6337 	else {
 6338 		query_result->init(NULL, myds, this);
 6339 	}
 6340 	new_result = true;
```

## lib/PgSQL_ExplicitTxnStateMgr.cpp:307

```cpp
  307 bool PgSQL_ExplicitTxnStateMgr::handle_transaction(std::string_view input) {
  308 	TxnCmd cmd = tx_parser.parse(input);
  309     switch (cmd.type) {
  310     case TxnCmd::BEGIN:
  311         start_transaction();
  312         break;
  313     case TxnCmd::COMMIT:
  314         commit();
  315         break;
  316     case TxnCmd::ROLLBACK:
  317         rollback(false);
  318         break;
  319 	case TxnCmd::ROLLBACK_AND_CHAIN:
  320         rollback(true);
  321         break;
  322     case TxnCmd::SAVEPOINT:
  323         return add_savepoint(cmd.savepoint);
  324     case TxnCmd::RELEASE:
  325         return release_savepoint(cmd.savepoint);
  326     case TxnCmd::ROLLBACK_TO:
  327         return rollback_to_savepoint(cmd.savepoint);
  328 	default:
  329 		// Unknown command
  330         return false;
  331     }
  332 	return true;
  333 }
  334
  335 void PgSQL_ExplicitTxnStateMgr::reset_state() {
  336
  337     for (auto& tran_state : transaction_state) {
```

## lib/PgSQL_ExplicitTxnStateMgr.cpp:396

```cpp
  396 TxnCmd PgSQL_TxnCmdParser::parse(std::string_view input) noexcept {
  397     TxnCmd cmd;
  398
  399     if (input.empty()) return cmd;
  400
  401     // Extract first word without full tokenization
  402     size_t start = 0;
  403     size_t end = 0;
  404
  405     while (start < input.size() && fast_isspace(input[start])) {
  406         start++;
  407     }
  408
  409     if (start >= input.size()) return cmd;
  410
  411     // Find end of first word
  412     end = start;
  413     bool in_quote = false;
  414     char quote_char = 0;
  415
  416     while (end < input.size()) {
  417         char c = input[end];
  418
  419         if (!in_quote && (c == '"' || c == '\'')) {
  420             // If we hit a quote at the start, this isn't a transaction command
  421             return cmd;
  422         }
  423
  424         if (fast_isspace(c) || c == ';') {
  425             break;
  426         }
  427
  428         end++;
  429     }
  430
  431     std::string_view first_word = input.substr(start, end - start);
  432
  433     // Check if this is a transaction command we care about
  434 	TxnCmd::Type cmd_type = TxnCmd::UNKNOWN;
  435
  436     // Parse transaction commands regardless of current transaction state.
  437     // This is required for pipeline mode where multiple commands are sent
  438     // before ReadyForQuery packets return the actual transaction status.
  439     if (iequals(first_word, "begin")) {
  440         cmd.type = TxnCmd::BEGIN;
  441         return cmd;
  442     } else if (iequals(first_word, "start")) {
  443         cmd_type = TxnCmd::BEGIN;
  444     } else if (iequals(first_word, "savepoint")) {
  445         cmd_type = TxnCmd::SAVEPOINT;
  446     } else if (iequals(first_word, "release")) {
  447         cmd_type = TxnCmd::RELEASE;
  448     } else if (iequals(first_word, "rollback") || iequals(first_word, "abort")) {
  449         // ABORT is a synonym for ROLLBACK (including ABORT AND CHAIN = ROLLBACK AND CHAIN)
  450         cmd_type = TxnCmd::ROLLBACK;
  451     } else if (iequals(first_word, "commit") || iequals(first_word, "end")) {
  452         cmd.type = TxnCmd::COMMIT;
  453         return cmd;
  454     }
  455
  456     // If not a transaction command, return early
  457     if (cmd_type == TxnCmd::UNKNOWN) {
  458         return cmd;
  459     }
  460
  461     // Continue tokenization from where we left off
  462     tokens.clear();
  463
```

## lib/PgSQL_Query_Processor.cpp:659

```cpp
  659 static enum PGSQL_QUERY_command select_target_command_type(const char* p) {
  660 	enum PGSQL_QUERY_command cmd = PGSQL_QUERY_SELECT;
  661 	size_t len = 0;
  662 	if (pgsql_stmt_first_keyword_is(p, "pg_cancel_backend")) {
  663 		cmd = PGSQL_QUERY_CANCEL_BACKEND;
  664 		len = sizeof("pg_cancel_backend") - 1;
  665 	} else if (pgsql_stmt_first_keyword_is(p, "pg_terminate_backend")) {
  666 		cmd = PGSQL_QUERY_TERMINATE_BACKEND;
  667 		len = sizeof("pg_terminate_backend") - 1;
  668 	} else {
  669 		return PGSQL_QUERY_SELECT;
  670 	}
  671 	// PostgreSQL takes a comment for whitespace, so "pg_cancel_backend/*x*/(1)" is a call too.
  672 	// Nothing after the name, or a comment the text ends inside (a cut prefix), counts like
  673 	// the end of the text.
  674 	p = pgsql_stmt_skip_lead(p + len, NULL);
  675 	return (p == NULL || *p == '(') ? cmd : PGSQL_QUERY_SELECT;
```

## lib/PgSQL_Query_Processor.cpp:798

```cpp
  798 static enum PGSQL_QUERY_command legacy_command_type(const char* text) {
  799 	enum PGSQL_QUERY_command ret = PGSQL_QUERY_UNKNOWN;
  800 	char c1;
  801
  802 	tokenizer_t tok;
  803 	tokenizer(&tok, text, " ;", TOKENIZER_NO_EMPTIES);
  804 	char* token = NULL;
  805 __get_token:
  806 	token = (char*)tokenize(&tok);
  807 	if (token == NULL) {
  808 		goto __exit__query_parser_command_type;
  809 	}
  810 __remove_parenthesis:
  811 	if (token[0] == '(') {
  812 		if (strlen(token) > 1) {
  813 			token++;
  814 			goto __remove_parenthesis;
  815 		}
  816 		else {
  817 			goto __get_token;
  818 		}
  819 	}
  820 	c1 = token[0];
  821 	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Command:%s Prefix:%c\n", token, c1);
  822 	switch (c1) {
```

## lib/PgSQL_Query_Processor.cpp:1223

```cpp
 1223 		}
 1224 		break;
 1225 	case 's':
 1226 	case 'S':
 1227 		if (!strcasecmp("SAVEPOINT", token)) {
 1228 			ret = PGSQL_QUERY_SAVEPOINT;
 1229 			break;
 1230 		}
 1231 		if (!strcasecmp("SELECT", token)) {
 1232 			token = (char*)tokenize(&tok);
 1233 			if (token == NULL) break;
 1234 			ret = select_target_command_type(token);
 1235 			break;
 1236 		}
```

## lib/Query_Processor.cpp:3476

```cpp
 3476 void Query_Processor<QP_DERIVED>::query_parser_update_counters(TypeSession* sess, uint64_t digest_total, uint64_t digest,
 3477 	char* digest_text, unsigned long long t) {
 3478
 3479 	if (digest_text) {
 3480 		char* ca = (char*)"";
 3481 		if (GET_THREAD_VARIABLE(query_digests_track_hostname)) {
 3482 			if (sess->client_myds) {
 3483 				if (sess->client_myds->addr.addr) {
 3484 					ca = sess->client_myds->addr.addr;
 3485 				}
 3486 			}
 3487 		}
 3488 		// this code is executed only if digest_text is not NULL , that means mysql_thread___query_digests was true when the query started
 3489 		uint64_t hash2;
 3490 		SpookyHash myhash;
 3491 		myhash.Init(19,3);
 3492 		assert(sess);
 3493 		assert(sess->client_myds);
 3494 		assert(sess->client_myds->myconn);
 3495 		assert(sess->client_myds->myconn->userinfo);
 3496 		auto *ui=sess->client_myds->myconn->userinfo;
 3497 		assert(ui->username);
 3498 		assert(ui->schemaname);
 3499 		myhash.Update(ui->username,strlen(ui->username));
 3500 		myhash.Update(&digest,sizeof(digest));
 3501 		myhash.Update(ui->schemaname,strlen(ui->schemaname));
 3502 		myhash.Update(&sess->current_hostgroup,sizeof(sess->current_hostgroup));
 3503 		myhash.Update(ca,strlen(ca));
 3504 		myhash.Final(&digest_total,&hash2);
 3505 		update_query_digest(digest_total, digest, digest_text, sess->current_hostgroup, ui, t, sess->thread->curtime, ca,
 3506 			sess->CurrentQuery.affected_rows, sess->CurrentQuery.rows_sent);
 3507 	}
 3508 }
 3509
 3510 /**
 3511  * @brief Record one query against its digest, creating the entry if needed.
 3512  *
 3513  * @par Locking
 3514  * Two phases. The common case -- a digest that already exists -- only needs the
 3515  * map to stay stable while the entry is located and updated, so it takes
 3516  * `digest_rwlock` for *reading*. `QP_query_digest_stats::add_time()` is safe
 3517  * under a shared lock because the counters it touches are atomic, so several
 3518  * threads can account against the same digest at once instead of serialising on
 3519  * an exclusive lock as this function used to.
 3520  *
 3521  * Only a digest seen for the first time needs the write lock, to insert into
 3522  * `digest_umap` (and `digest_text_umap` when digest text normalisation is on).
 3523  * The map is re-checked after upgrading, because the read lock is dropped
 3524  * before the write lock is taken and another thread may have inserted the same
 3525  * digest in between.
 3526  *
 3527  * @note The read lock does not make a group of counters mutually consistent;
 3528  *   see the concurrency contract on QP_query_digest_stats. Readers that need a
 3529  *   coherent view must snapshot.
 3530  */
 3531 template <typename QP_DERIVED>
 3532 void Query_Processor<QP_DERIVED>::update_query_digest(uint64_t digest_total, uint64_t digest, char* digest_text, int hid,
 3533 	TypeConnInfo* ui, unsigned long long t, unsigned long long n, const char* client_addr, unsigned long long rows_affected,
 3534 	unsigned long long rows_sent) {
 3535 	QP_query_digest_stats* qds;
 3536 	std::unordered_map<uint64_t, void*>::iterator it;
 3537
 3538 	pthread_rwlock_rdlock(&digest_rwlock);
 3539 	it=digest_umap.find(digest_total);
 3540 	if (it != digest_umap.end()) {
 3541 		qds=(QP_query_digest_stats *)it->second;
 3542 		qds->add_time(t,n,rows_affected,rows_sent);
 3543 		pthread_rwlock_unlock(&digest_rwlock);
 3544 		return;
 3545 	}
 3546 	pthread_rwlock_unlock(&digest_rwlock);
 3547
 3548 	pthread_rwlock_wrlock(&digest_rwlock);
 3549 	it=digest_umap.find(digest_total);
 3550 	if (it != digest_umap.end()) {
 3551 		qds=(QP_query_digest_stats *)it->second;
 3552 		qds->add_time(t,n,rows_affected,rows_sent);
 3553 	} else {
 3554 		char *dt = NULL;
 3555 		if (GET_THREAD_VARIABLE(query_digests_normalize_digest_text)==false) {
 3556 			dt = digest_text;
 3557 		}
 3558 		qds=new QP_query_digest_stats(ui->username, ui->schemaname, digest, dt, hid, client_addr, GET_THREAD_VARIABLE(query_digests_max_digest_length));
 3559 		qds->add_time(t,n, rows_affected,rows_sent);
 3560 		digest_umap.insert(std::make_pair(digest_total,(void *)qds));
 3561 		if (GET_THREAD_VARIABLE(query_digests_normalize_digest_text)==true) {
 3562 			const uint64_t dig = digest;
 3563 			std::unordered_map<uint64_t, char *>::iterator it2;
 3564 			it2=digest_text_umap.find(dig);
 3565 			if (it2 != digest_text_umap.end()) {
```

## lib/PgSQL_Thread.cpp:82

```cpp
   82 // Opt-in diagnostics for the phased outer worker loop. Preserve errno because
   83 // the first boundary is immediately after poll(), before its error handling.
   84 static void pgsql_loop_timing_point(unsigned phase, int poll_rc = 0) {
   85     static const char *path = getenv("PX_PGSQL_LOOP_TIMING");
   86     if (!path) return;
   87     const int saved_errno = errno;
   88     struct Stamp { uint64_t wall, cpu; };
   89     auto stamp = []() -> Stamp {
   90         timespec wall{}, cpu{};
   91         clock_gettime(CLOCK_MONOTONIC, &wall);
   92         clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu);
```

## lib/pgsql_tokenizer.cpp:2830

```cpp
 2830 char* pgsql_query_digest_and_first_comment(const char* const q, int q_len, char** const fst_cmnt, char* const buf, const options* opts) {
 2831 	// No DEBUG-only memset of the caller's buffer here: callers may pass a
 2832 	// buffer of exactly pgsql_query_digest_buffer_size() bytes, which can be
 2833 	// smaller than the 127 bytes a fixed-size clear would write (#6451).
 2834
 2835 	/* buffer to store first comment. */
 2836 	int d_max_len = get_digest_max_len(q_len, opts->max_query_length);
 2837 	const int res_max_len = get_result_buffer_len(d_max_len, opts);
 2838 	char* res = get_result_buffer(res_max_len, buf);
 2839
 2840 #ifdef DEBUG
 2841 	res[res_max_len] = 0;
 2842 #endif
 2843
 2844 	// state shared between all the parsing states
 2845 	struct shared_st shared_st;
 2846 	memset(&shared_st, 0, sizeof(struct shared_st));
 2847 	init_shared_st(&shared_st, q, q_len, d_max_len, res);
 2848 	// With 'keep_comment' the digest can be longer than the query ('res_max_len' > 'd_max_len').
 2849 	shared_st.res_max_len = res_max_len;
 2850
 2851 	// individual states for stages
 2852 	struct stage_1_st stage_1_st;
 2853 	memset(&stage_1_st, 0, sizeof(struct stage_1_st));
 2854 	init_stage_1_st(&stage_1_st);
 2855 	struct stage_2_st stage_2_st;
 2856 	struct stage_3_st stage_3_st;
 2857 	struct stage_4_st stage_4_st;
 2858 	memset(&stage_2_st, 0, sizeof(struct stage_2_st));
 2859 	memset(&stage_3_st, 0, sizeof(struct stage_3_st));
 2860 	memset(&stage_4_st, 0, sizeof(struct stage_4_st));
 2861
 2862 	char min_digest_size = 0;
 2863
 2864 	// TODO: This may requires a stopping point, configurable or not, otherwise parsing can become slow for
```

## lib/pgsql_tokenizer.cpp:2883

```cpp
 2883 		stage_3_parsing(&shared_st, &stage_1_st, &stage_3_st, opts);
 2884 		stage_4_parsing(&shared_st, &stage_1_st, &stage_4_st, opts);
 2885
 2886 		// compute the compression offset of the whole iteration
 2887 		shared_st.gl_c_offset = stage_1_st.pre_it_pos - shared_st.res_cur_pos;
 2888 		if (
 2889 			shared_st.q_cur_pos >= shared_st.q_len ||
 2890 			digest_len_limit(&shared_st, &stage_1_st.cmnt_type_1_st) <= (shared_st.res_cur_pos - shared_st.res_init_pos) ||
 2891 			shared_st.gl_c_offset == 0
 2892 		) {
 2893 			min_digest_size = 1;
 2894 		} else {
 2895 			// we need to update the shared state for processing again from the previous ending point
 2896 			char* new_start_point = shared_st.res_cur_pos;
 2897 			shared_st.res_it_init_pos = new_start_point;
 2898 			shared_st.res_cur_pos = new_start_point;
 2899 			shared_st.res_pre_pos = new_start_point;
 2900 		}
 2901 	}
 2902
 2903 	final_stage(&shared_st, &stage_1_st, opts);
 2904
 2905 	return res;
 2906 }
 2907
 2908 static __attribute__((always_inline)) inline
 2909 enum p_st process_literal_string_space_rm(shared_st* shared_st, literal_string_st* str_st) {
 2910 	enum p_st next_state = st_literal_string;
 2911
 2912 	// process the first delimiter
```
