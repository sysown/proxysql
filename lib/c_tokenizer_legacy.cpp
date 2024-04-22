/*
	this file is here only for reference.
	It includes the old mysql_query_digest_and_first_comment() , outdated since ProxySQL 2.4.0
*/
char *mysql_query_digest_and_first_comment(char *s, int _len, char **first_comment, char *buf){
	int i = 0;

	char cur_comment[FIRST_COMMENT_MAX_LENGTH];
	cur_comment[0]=0;
	int ccl=0;
	int cmd=0;

	int len = _len;
	if (_len > mysql_thread___query_digests_max_query_length) {
		len = mysql_thread___query_digests_max_query_length;
	}
	char *r = buf;
	if (r==NULL) {
		r = (char *) malloc(len + SIZECHAR);
	}
	char *p_r = r;
	char *p_r_t = r;

	char prev_char = 0;
	char qutr_char = 0;

	char flag = 0;
	char fc=0;
	int fc_len=0;

	char fns=0;

	bool lowercase=0;
	bool replace_null=0;
	bool replace_number=0;

	char grouping_digest=0;
	char grouping_limit_exceeded=0;
	int grouping_count=0;
	int grouping_lim = mysql_thread___query_digests_grouping_limit;

	lowercase=mysql_thread___query_digests_lowercase;
	replace_null = mysql_thread___query_digests_replace_null;
	replace_number = mysql_thread___query_digests_no_digits;

	while(i < len)
	{
		// Handy for debugging purposes
		// ============================
		// printf(
		// 	"state-1: { flag: `%d`, prev_char: `%c`, s: `%s`, p_r: `%s`, r: `%s`}\n",
		// 	flag, prev_char, s, p_r, r
		// );
		// ============================

		// =================================================
		// START - read token char and set flag what's going on.
		// =================================================
		if(flag == 0)
		{
			// store current position
			p_r_t = p_r;

			// comment type 1 - start with '/*'
			if(prev_char == '/' && *s == '*')
			{
				ccl=0;
				flag = 1;
				if (i != (len-1) && *(s+1)=='!')
					cmd=1;
			}

			// comment type 2 - start with '#'
			else if(*s == '#')
			{
				flag = 2;
			}

			// comment type 3 - start with '--'

			// NOTE: Looks like the general rule for parsing comments of this type could simply be:
			//
			//  - `.*--.*` which could be translated into `(*s == '-' && *(s+1) == '-')`.
			//
			// But this can not hold, since the first '-' could have been consumed previously, for example
			// during the parsing of a digit:
			//
			// - `select 1.1-- final_comment\n`
			//
			// For this reason 'prev_char' needs to be checked too when searching for the `--` pattern.
			else if(i != (len-1) && prev_char == '-' && *s == '-' && ((*(s+1)==' ') || (*(s+1)=='\n') || (*(s+1)=='\r') || (*(s+1)=='\t') ))
			{
				flag = 3;
			}

			// Previous character can be a consumed ' ' instead of '-' as in the previous case, for this
			// reason, we need to look ahead for '--'.
			//
			// NOTE: There is no reason for not checking for the subsequent space char that should follow
			// the '-- ', otherwise we would consider valid queries as `SELECT --1` like comments.
			else if (i != (len-1) && *s == '-' && (*(s+1)=='-')) {
				if (prev_char != '-') {
					flag = 3;
				}
				else if (i==0) {
					flag = 3;
				}
			}

			// string - start with '
			else if(*s == '\'' || *s == '"')
			{
				flag = 4;
				qutr_char = *s;
			}

			// may be digit - start with digit
			else if(is_token_char(prev_char) && is_digit_char(*s))
			{
				flag = 5;
				if(len == i+1)
					continue;
			}

			// not above case - remove duplicated space char
			else
			{
				flag = 0;
				if (fns==0 && is_space_char(*s)) {
					s++;
					i++;
					continue;
				}
				if (fns==0) fns=1;
				if(is_space_char(prev_char) && is_space_char(*s)){
					prev_char = ' ';
					*p_r = ' ';
					s++;
					i++;
					continue;
				}
				if (replace_number) {
					if (!is_digit_char(prev_char) && is_digit_char(*s)) {
						*p_r++ = '?';
						while(*s != '\0' && is_digit_char(*s)) {
							s++;
							i++;
						}
					}
				}
				{
					char* p = p_r - 2;
					// suppress spaces before arithmetic operators
					if (p >= r && is_space_char(prev_char) && is_arithmetic_op(*s)) {
						if (*p == '?') {
							prev_char = *s;
							--p_r;
							*p_r++ = *s;
							s++;
							i++;
							continue;
						}
					}
					// suppress spaces before and after commas
					if (p >= r && is_space_char(prev_char) && ((*s == ',') || (*p == ','))) {
						if (*s == ',') {
							--p_r;
							// only copy the comma if we are not grouping a query
							if (!grouping_limit_exceeded) {
								*p_r++ = *s;
							}
							prev_char = ',';
							s++;
							i++;
						} else {
							prev_char = ',';
							--p_r;
						}
						continue;
					}
					// suppress spaces before closing brackets when grouping or mark is present
					if (p >= r && (*p == '.' || *p == '?') && is_space_char(prev_char) && (*s == ')')) {
						prev_char = *s;
						--p_r;
						*p_r++ = *s;
						s++;
						i++;
						continue;
					}
				}
				if (replace_null) {
				if (*s == 'n' || *s == 'N') { // we search for NULL , #2171
					if (i && is_token_char(prev_char)) {
						if (len>=4) {
							if (i<len-3) {
								// it is only 4 chars, let's skip strncasecmp
								if (*(s+1) == 'u' || *(s+1) == 'U') {
									if (*(s+2) == 'l' || *(s+2) == 'L') {
										if (*(s+3) == 'l' || *(s+3) == 'L') {
											if (i==len-4) {
												// replace spaces before NULL values
												if (*(p_r - 1) == ' ' && is_token_char(*(p_r - 2))) {
													p_r--;
												}

												replace_with_q_mark(
													grouping_digest, grouping_lim, &grouping_count,
													&p_r, &grouping_limit_exceeded
												);

												*p_r = 0;
												return r;
											} else {
												if (is_token_char(*(s+4))){
													// replace spaces before NULL values
													if (*(p_r - 1) == ' ' && is_token_char(*(p_r - 2))) {
														p_r--;
													}

													replace_with_q_mark(
														grouping_digest, grouping_lim, &grouping_count,
														&p_r, &grouping_limit_exceeded
													);

													s+=4;
													i+=4;
												}
											}
										}
									}
								}
							}
						}
					}
				}
				}
			}
		}

		// =================================================
		// PROCESS and FINISH - do something on each case
		// =================================================
		else
		{
			// --------
			// comment
			// --------
			if (flag == 1) {
				if (cmd) {
					if (ccl<FIRST_COMMENT_MAX_LENGTH-1) {
						cur_comment[ccl]=*s;
						ccl++;
					}
				}
				if (fc==0) {
					fc=1;
				}
				if (fc==1) {
					if (fc_len<FIRST_COMMENT_MAX_LENGTH-1) {
						if (*first_comment==NULL) {
							*first_comment=(char *)malloc(FIRST_COMMENT_MAX_LENGTH);
							*(*first_comment + FIRST_COMMENT_MAX_LENGTH - 1) = 0;
						}
						char *c=*first_comment+fc_len;
						*c = !is_space_char(*s) ? *s : ' ';
						fc_len++;
					}
					if (prev_char == '*' && *s == '/') {
						if (fc_len>=2) fc_len-=2;
						char *c=*first_comment+fc_len;
						*c=0;
						//*first_comment[fc_len]=0;
						fc=2;
					}
				}
			}
			if(
				// comment type 1 - /* .. */
				(flag == 1 && prev_char == '*' && *s == '/') ||

				// comment type 2 - # ... \n
				(flag == 2 && (*s == '\n' || *s == '\r' || (i == len - 1) ))
				||
				// comment type 3 - -- ... \n
				(flag == 3 && (*s == '\n' || *s == '\r' || (i == len -1) ))
			)
			{
				p_r = p_r_t;
				if (flag == 1 || (i == len -1)) {
					p_r -= SIZECHAR;
				}
				if (cmd) {
					cur_comment[ccl]=0;
					if (ccl>=2) {
						ccl-=2;
						cur_comment[ccl]=0;
						char el=0;
						int fcc=0;
						while (el==0 && fcc<ccl ) {
							switch (cur_comment[fcc]) {
								case '/':
								case '*':
								case '!':
								case '0':
								case '1':
								case '2':
								case '3':
								case '4':
								case '5':
								case '6':
								case '7':
								case '8':
								case '9':
								case ' ':
									fcc++;
									break;
								default:
									el=1;
									break;
							}
						}
						if (el) {
							memcpy(p_r,cur_comment+fcc,ccl-fcc);
							p_r+=(ccl-fcc);
							*p_r++=' ';
						}
					}
					cmd=0;
				}
				if (flag == 1 && prev_char == '*' && *s == '/') {
					if (r != p_r && *p_r != ' ') { // not at the beginning, and previous char is not ' '
						*p_r++ = ' ';
					}
				}
				prev_char = ' ';
				flag = 0;
				s++;
				i++;
				continue;
			}

			// --------
			// string
			// --------
			else if(flag == 4)
			{
				// Last char process
				if(len == i + 1)
				{
					char *_p = p_r_t;
					_p-=3;
					p_r = p_r_t;
					if ( _p >= r && ( *(_p+2) == '-' || *(_p+2) == '+') ) {
						if  (
							( *(_p+1) == ',' ) || ( *(_p+1) == '(' ) ||
							( ( *(_p+1) == ' ' ) && ( *_p == ',' || *_p == '(' ) )
						) {
							p_r--;
						}
					}

					replace_with_q_mark(
						grouping_digest, grouping_lim, &grouping_count, &p_r, &grouping_limit_exceeded
					);

					flag = 0;
					break;
				}

				// need to be ignored case
				if(p_r > p_r_t + SIZECHAR)
				{
					if(
						(prev_char == '\\' && *s == '\\') ||		// to process '\\\\', '\\'
						(prev_char == '\\' && *s == qutr_char) ||	// to process '\''
						(prev_char == qutr_char && *s == qutr_char)	// to process ''''
					)
					{
						prev_char = 'X';
						s++;
						i++;
						continue;
					}
				}

				// satisfied closing string - swap string to ?
				if(*s == qutr_char && (len == i+1 || *(s + SIZECHAR) != qutr_char))
				{
					char *_p = p_r_t;
					_p-=3;
					p_r = p_r_t;
					if ( _p >= r && ( *(_p+2) == '-' || *(_p+2) == '+') ) {
						if  (
							( *(_p+1) == ',' ) || ( *(_p+1) == '(' ) ||
							( ( *(_p+1) == ' ' ) && ( *_p == ',' || *_p == '(' ) )
						) {
							p_r--;
						}
					}

					// Remove spaces before each literal found
					if ( _p >= r && is_space_char(*(_p + 2)) && !is_normal_char(*(_p + 1))) {
						if ( _p >= r && ( *(_p+3) == '\''|| *(_p+3) == '"' )) {
							p_r--;
						}
					}

					replace_with_q_mark(
						grouping_digest, grouping_lim, &grouping_count, &p_r, &grouping_limit_exceeded
					);

					prev_char = qutr_char;
					qutr_char = 0;
					flag = 0;
					if(i < len)
						s++;
					i++;
					continue;
				}
			}

			// --------
			// digit
			// --------
			else if(flag == 5)
			{
				// last single char
				if(p_r_t == p_r)
				{
					char *_p = p_r_t;
					_p-=3;
					if ( _p >= r && ( *(_p+2) == '-' || *(_p+2) == '+') ) {
						if  (
							( *(_p+1) == ',' ) || ( *(_p+1) == '(' ) ||
							( ( *(_p+1) == ' ' ) && ( *_p == ',' || *_p == '(' ) )
						) {
							p_r--;
						}
					}
					if ( _p >= r && is_space_char(*(_p + 2))) {
						if ( _p >= r && ( *(_p+1) == '-' || *(_p+1) == '+' || *(_p+1) == '*' || *(_p+1) == '/' || *(_p+1) == '%' || *(_p+1) == ',')) {
							p_r--;
						}
					}
					*p_r++ = '?';
					i++;
					continue;
				}

				// is float
				if (*s == '.' || *s == 'e' || ((*s == '+' || *s == '-') && prev_char == 'e')) {
					prev_char = *s;
					i++;
					s++;
					continue;
				}

				// token char or last char
				if(is_token_char(*s) || len == i+1)
				{
					if(is_digit_string(p_r_t, p_r))
					{
						char *_p = p_r_t;
						_p-=3;
						p_r = p_r_t;
						// remove symbol and keep parenthesis or comma
						if ( _p >= r && ( *(_p+2) == '-' || *(_p+2) == '+') ) {
							if  (
								( *(_p+1) == ',' ) || ( *(_p+1) == '(' ) ||
								( ( *(_p+1) == ' ' ) && ( *_p == ',' || *_p == '(' ) )
							) {
								p_r--;
							}
						}

						// Remove spaces before number counting with possible '.' presence
						if (_p >= r && *_p == '.' && (*(_p + 1) == ' ' || *(_p + 1) == '.') && (*(_p+2) == '-' || *(_p+2) == '+') ) {
							if (*(_p + 1) == ' ') {
								p_r--;
							}
							p_r--;
						}

						// Remove spaces after a opening bracket when followed by a number
						if (_p >= r && *(_p+1) == '(' && *(_p+2) == ' ') {
							p_r--;
						}

						// Remove spaces before number
						if ( _p >= r && is_space_char(*(_p + 2))) {
							// A point can be found prior to a number in case of query grouping
							if ( _p >= r && ( *(_p+1) == '-' || *(_p+1) == '+' || *(_p+1) == '*' || *(_p+1) == '/' || *(_p+1) == '%' || *(_p+1) == ',' || *(_p+1) == '.')) {
								p_r--;
							}
						}

						replace_with_q_mark(
							grouping_digest, grouping_lim, &grouping_count, &p_r, &grouping_limit_exceeded
						);

						if(len == i+1)
						{
							if(is_token_char(*s))
								*p_r++ = *s;
							i++;
							continue;
						}
					} else {
						// collapse any digits found in the string
						if (replace_number) {
							int str_len = p_r - p_r_t + 1;
							int collapsed = 0;

							for (int j = 0; j < str_len; j++) {
								char* const c_p_r_t = ((char*)p_r_t + j);
								char* const n_p_r_t = ((char*)p_r_t + j + 1);

								if (is_digit_char(*c_p_r_t) && is_digit_char(*n_p_r_t)) {
									memmove(c_p_r_t, c_p_r_t + 1, str_len - j);
									collapsed += 1;
								}
							}

							p_r -= collapsed;

							int new_str_len = p_r - p_r_t + 1;
							for (int j = 0; j < new_str_len; j++) {
								char* const c_p_r_t = ((char*)p_r_t + j);
								if (is_digit_char(*c_p_r_t)) {
									*c_p_r_t = '?';
								}
							}
						}
					}

					flag = 0;
				}
			}
		}

		// =================================================
		// COPY CHAR
		// =================================================
		// convert every space char to ' '
		if (*s == ')') {
			if (grouping_digest > 0) {
				grouping_digest -= 1;
			};
			grouping_count = 0;
			grouping_limit_exceeded = 0;
		}

		if (lowercase==0) {
			*p_r++ = !is_space_char(*s) ? *s : ' ';
		} else {
			*p_r++ = !is_space_char(*s) ? (tolower(*s)) : ' ';
		}

		if (*s == '(') {
			grouping_digest += 1;
			grouping_count = 0;
			grouping_limit_exceeded = 0;
		}

		prev_char = *s++;

		i++;
	}

	// remove a trailing space
	if (p_r>r) {
		char *e=p_r;
		e--;
		if (*e==' ') {
			*e=0;
			// maybe 2 trailing spaces . It happens with comments
			e--;
			if (*e==' ') {
				*e=0;
			}
		}
	}

	*p_r = 0;

	// process query stats
	return r;
}
