%option reentrant noyywrap nounput noinput batch case-insensitive
%option prefix="mysql_yy"
%option extra-type="MySQLParser::Parser*"

%{

// #define ECHO /* This makes ECHO do nothing */

// C++ code to be included in the generated lexer
#include "MySQL_Parser.h"         // For MySQLParser::Parser, yyscan_t
#include "MySQL_AST.h"            // For MySQLParser::AstNode, etc.
#include "MySQL_Parser.tab.h"     // Bison-generated: token enums, defines union MYSQL_YYSTYPE

#include <cassert>
#include <string>
#include <vector>

union MYSQL_YYSTYPE;
#undef YY_DECL
#define YY_DECL int mysql_yylex (\
	union MYSQL_YYSTYPE *yylval_param,\
	MYSQL_YYLTYPE* yylloc,\
	yyscan_t yyscanner,\
	MySQLParser::Parser* parser\
)

#define SAVE_TOKEN_STRING yylval_param->str_val = new std::string(yytext)
#define YY_USER_ACTION                          \
	yylloc->first_line = yylloc->last_line;     \
	yylloc->first_column = yylloc->last_column; \
												\
	for(int i = 0; yytext[i] != '\0'; i++) {    \
		if(yytext[i] == '\n') {                 \
			yylloc->last_line++;                \
			yylloc->last_column = 0;            \
		} else {                                \
			yylloc->last_column++;              \
		}                                       \
	}

%}

%x COMMENT
%x COMMAND
%x HINT
%x SQSTRING
%x DQSTRING
%x BTIDENT

%%

 /* Rules for the lexer */

<INITIAL>{
	"/*"                  { BEGIN(COMMENT); }
	"/*!"[0-9]*           {
		if (!parser) { assert(0 && "Invalid Lexer initialization, parser **must** be supplied as context"); }

		if (!parser->get_opts().srv_ver) {
			BEGIN(COMMAND);
		} else {
			char ver[7] { 0 };
			size_t ver_len = strlen(yytext + 3);

			if (ver_len == 5) {
				ver[0] = '0';
				ver[1] = *(yytext + 3);

				strncpy(ver + 2, yytext + 4, 4);
			} else if (ver_len == 6) {
				strncpy(ver, yytext + 3, 6);
			}

			int cmp = strcasecmp(parser->get_opts().srv_ver, ver);
			if (cmp >= 0) {
				BEGIN(COMMAND);
			} else {
				BEGIN(COMMENT);
			}
		}
	}
	"*/"                  { /* Ignore COMMENT ending; reachable by COMMAND */ }
	"-- ".*               { /* MySQL -- comment (note space); ignore */ }
	"--\n"                { /* MySQL -- comment followed by newline; ignore */ }
	"#".*                 { /* MySQL # comment; ignore */ }

	[ \t\n\r]+            { /* Ignore whitespace and carriage returns */ }

	/* Keywords - Specific keywords must come BEFORE the generic identifier rule */
	"SELECT"              { return TOKEN_SELECT; }
	"FROM"                { return TOKEN_FROM; }
	"INSERT"              { return TOKEN_INSERT; }
	"INTO"                { return TOKEN_INTO; }
	"VALUES"              { return TOKEN_VALUES; }
	"QUIT"                { SAVE_TOKEN_STRING; return TOKEN_QUIT; }

	"SET"                 { return TOKEN_SET; }
	"NAMES"               { return TOKEN_NAMES; }
	"CHARACTER"           { return TOKEN_CHARACTER; }
	"CHARSET"             { return TOKEN_CHARSET; }
	"GLOBAL"              { return TOKEN_GLOBAL; }
	"SESSION"             { return TOKEN_SESSION; }
	"PERSIST"             { return TOKEN_PERSIST; }
	"PERSIST_ONLY"        { return TOKEN_PERSIST_ONLY;}
	"DEFAULT"             { return TOKEN_DEFAULT; }
	"COLLATE"             { return TOKEN_COLLATE; }

	"SHOW"                { return TOKEN_SHOW; }
	/* FULL is already defined for JOINs, will be reused */
	/* FIELDS is already defined for INTO OUTFILE, will be reused */
	"DATABASES"           { return TOKEN_DATABASES; }
	"BEGIN"               { return TOKEN_BEGIN; }
	"COMMIT"              { return TOKEN_COMMIT; }
	"IS"                  { return TOKEN_IS; }
	"NULL"                { return TOKEN_NULL_KEYWORD; }
	"TRUE"                { return TOKEN_TRUE; }
	"FALSE"               { return TOKEN_FALSE; }
	"UNKNOWN"             { return TOKEN_UNKNOWN; }

	/* Literal SET values (options) */
	"BINARY"              { return TOKEN_BINARY; }
	"ROW"                 { return TOKEN_ROW; }
	"SYSTEM"              { return TOKEN_SYSTEM; }

	"NOT"                 { return TOKEN_NOT; }
	"BETWEEN"             { return TOKEN_BETWEEN; }
	"MEMBER"              { return TOKEN_MEMBER; }
	"ESCAPE"              { return TOKEN_ESCAPE; }
	"REGEXP"              { return TOKEN_REGEXP; }

	"OFFSET"              { return TOKEN_OFFSET; }

	"DELETE"              { return TOKEN_DELETE; }
	"LOW_PRIORITY"        { return TOKEN_LOW_PRIORITY; }
	"QUICK"               { return TOKEN_QUICK; }
	"IGNORE"              { return TOKEN_IGNORE_SYM; }
	"USING"               { return TOKEN_USING; }
	"ORDER"               { return TOKEN_ORDER; }
	"BY"                  { return TOKEN_BY; }
	"LIMIT"               { return TOKEN_LIMIT; }
	"ASC"                 { return TOKEN_ASC; }
	"DESC"                { return TOKEN_DESC; }
	"WHERE"               { return TOKEN_WHERE; }
	"AS"                  { return TOKEN_AS; }
	"DISTINCT"            { return TOKEN_DISTINCT; }
	"GROUP"               { return TOKEN_GROUP; }
	"ALL"                 { return TOKEN_ALL; }
	"ANY"                 { return TOKEN_ANY; }
	"HAVING"              { return TOKEN_HAVING; }
	"INTERVAL"            { return TOKEN_INTERVAL; }

	/* Boolean Operators */
	"OR"                  { return TOKEN_OR; }
	"XOR"                 { return TOKEN_XOR; }
	"AND"                 { return TOKEN_AND; }

	/* Arithmetic Operators */
	"DIV"                 { return TOKEN_DIV; }
	"MOD"                 { return TOKEN_MOD; }

	/* JOIN related keywords */
	"JOIN"                { return TOKEN_JOIN; }
	"INNER"               { return TOKEN_INNER; }
	"LEFT"                { return TOKEN_LEFT; }
	"RIGHT"               { return TOKEN_RIGHT; }
	"FULL"                { return TOKEN_FULL; }
	"OUTER"               { return TOKEN_OUTER; }
	"CROSS"               { return TOKEN_CROSS; }
	"NATURAL"             { return TOKEN_NATURAL; }
	"ON"                  { return TOKEN_ON; }

	/* Intervals */
	"DAY_HOUR"            { return TOKEN_DAY_HOUR; }
	"DAY_MICROSECOND"     { return TOKEN_DAY_MICROSECOND; }
	"DAY_MINUTE"          { return TOKEN_DAY_MINUTE; }
	"DAY_SECOND"          { return TOKEN_DAY_SECOND; }
	"HOUR_MICROSECOND"    { return TOKEN_HOUR_MICROSECOND; }
	"HOUR_MINUTE"         { return TOKEN_HOUR_MINUTE; }
	"HOUR_SECOND"         { return TOKEN_HOUR_SECOND; }
	"MINUTE_MICROSECOND"  { return TOKEN_MINUTE_MICROSECOND; }
	"MINUTE_SECOND"       { return TOKEN_MINUTE_SECOND; }
	"SECOND_MICROSECOND"  { return TOKEN_SECOND_MICROSECOND; }
	"YEAR_MONTH"          { return TOKEN_YEAR_MONTH; }

	/* Timestamps */
	"DAY"                 { return TOKEN_DAY; }
	"WEEK"                { return TOKEN_WEEK; }
	"HOUR"                { return TOKEN_HOUR; }
	"MINUTE"              { return TOKEN_MINUTE; }
	"MONTH"               { return TOKEN_MONTH; }
	"QUARTER"             { return TOKEN_QUARTER; }
	"SECOND"              { return TOKEN_SECOND; }
	"MICROSECOND"         { return TOKEN_MICROSECOND; }
	"YEAR"                { return TOKEN_YEAR; }

	/* New keywords for INTO, LOCKING */
	"OUTFILE"             { return TOKEN_OUTFILE; }
	"DUMPFILE"            { return TOKEN_DUMPFILE; }
	"FOR"                 { return TOKEN_FOR; }
	"UPDATE"              { return TOKEN_UPDATE; }
	"SHARE"               { return TOKEN_SHARE; }
	"OF"                  { return TOKEN_OF; }
	"NOWAIT"              { return TOKEN_NOWAIT; }
	"SKIP"                { return TOKEN_SKIP; }
	"LOCKED"              { return TOKEN_LOCKED; }

	/* Keywords for SET TRANSACTION (Query 1) */
	"TRANSACTION"         { return TOKEN_TRANSACTION; }
	"ISOLATION"           { return TOKEN_ISOLATION; }
	"LEVEL"               { return TOKEN_LEVEL; }
	"READ"                { return TOKEN_READ; }
	"ONLY"                { return TOKEN_ONLY; }
	"WRITE"               { return TOKEN_WRITE; }
	"COMMITTED"           { return TOKEN_COMMITTED; }
	"UNCOMMITTED"         { return TOKEN_UNCOMMITTED; }
	"REPEATABLE"          { return TOKEN_REPEATABLE; }
	"SERIALIZABLE"        { return TOKEN_SERIALIZABLE; }

	/* Keywords for MATCH AGAINST (Query 5) */
	"MATCH"               { return TOKEN_MATCH; }
	"AGAINST"             { return TOKEN_AGAINST; }
	"BOOLEAN"             { return TOKEN_BOOLEAN; }
	"MODE"                { return TOKEN_MODE; }
	"IN"                  { return TOKEN_IN; } /* For IN BOOLEAN MODE and IN operator */

	/* Keywords for INTO OUTFILE options */
	"FIELDS"              { return TOKEN_FIELDS; }
	"TERMINATED"          { return TOKEN_TERMINATED; }
	"OPTIONALLY"          { return TOKEN_OPTIONALLY; }
	"ENCLOSED"            { return TOKEN_ENCLOSED; }
	"ESCAPED"             { return TOKEN_ESCAPED; }
	"LINES"               { return TOKEN_LINES; }
	"STARTING"            { return TOKEN_STARTING; }

	/* Aggregate function keywords */
	"COUNT"               { return TOKEN_COUNT; }
	"SUM"                 { return TOKEN_SUM; }
	"AVG"                 { return TOKEN_AVG; }
	"MAX"                 { return TOKEN_MAX; }
	"MIN"                 { return TOKEN_MIN; }

	/* Extra keywords */
	"SOUNDS"              { return TOKEN_SOUNDS; }
	"LIKE"                { return TOKEN_LIKE; }

	/* Identifiers and Literals */
	"`"                   { yylval_param->str_val = new std::string("`"); BEGIN(BTIDENT); }

	"@@GLOBAL."           { return TOKEN_GLOBAL_VAR_PREFIX; }
	"@@SESSION."          { return TOKEN_SESSION_VAR_PREFIX; }
	"@@LOCAL."            { return TOKEN_SESSION_VAR_PREFIX; } /* local is alias for session */
	"@@PERSIST."          { return TOKEN_PERSIST_VAR_PREFIX; } /* MySQL 8 specific */
	"@@PERSIST_ONLY."     { return TOKEN_PERSIST_ONLY_VAR_PREFIX; } /* MySQL 8 specific */
	"@@"                  { return TOKEN_DOUBLESPECIAL; } /* For @@varname */
	"@"                   { return TOKEN_SPECIAL; } /* For @uservar */

	/* Generic Identifier - MUST BE AFTER specific keywords */
	[a-zA-Z_][a-zA-Z0-9_]* {
		SAVE_TOKEN_STRING;
		return TOKEN_IDENTIFIER;
	}

	"'"                   { yylval_param->str_val = new std::string("'"); BEGIN(SQSTRING); }
	"\""                  { yylval_param->str_val = new std::string("\""); BEGIN(DQSTRING); }

	/* Operators and Punctuation */
	"*"                   { return '*'; }
	"+"                   { return '+'; }
	"-"                   { return '-'; }
	"/"                   { return '/'; }
	"%"                   { return '%'; }
	"^"                   { return '^'; }
	"|"                   { return '|'; }
	"&"                   { return '&'; }
	"~"                   { return TOKEN_NEG; }
	"("                   { return TOKEN_LPAREN; }
	")"                   { return TOKEN_RPAREN; }
	";"                   { return TOKEN_SEMICOLON; }
	"."                   { return TOKEN_DOT; }
	","                   { return TOKEN_COMMA; }

	"="                   { return TOKEN_EQUAL; }
	"<"                   { return TOKEN_LESS; }
	">"                   { return TOKEN_GREATER; }
	"<="                  { return TOKEN_LESS_EQUAL; }
	">="                  { return TOKEN_GREATER_EQUAL; }
	"!="                  { return TOKEN_NOT_EQUAL; }
	"<>"                  { return TOKEN_NOT_EQUAL; }
	"<<"                  { return TOKEN_BITWISE_LSHIFT; }
	">>"                  { return TOKEN_BITWISE_RSHIFT; }

	[0-9]+("."[0-9]+)?([eE][+-]?[0-9]+)? { SAVE_TOKEN_STRING; return TOKEN_NUMBER_LITERAL; }
	0x[0-9a-fA-F]+        { SAVE_TOKEN_STRING; return TOKEN_NUMBER_LITERAL; } /* Hex literal */
	X'[0-9a-fA-F]*'       { SAVE_TOKEN_STRING; return TOKEN_STRING_LITERAL; } /* Hex string literal X'...' */

	.                     {
		char err_msg[100];
		snprintf(err_msg, sizeof(err_msg), "Lexer: Unknown character: '%s'", yytext);
		if (parser) {
			parser->internal_add_error(err_msg);
		} else {
			fprintf(stderr, "%s\n", err_msg);
		}
	}
}

<COMMENT>{
	"*/"                  { BEGIN(INITIAL); }
	[^*\n]+               { /* Eat comment content */ }
	"*"                   { /* Eat isolated asterisks */ }
	\n                    { /* Newlines in comments */ }
	<<EOF>>               {
		if(parser) {
			parser->internal_add_error("Unterminated /* comment");
		}

		BEGIN(INITIAL);
		return YY_NULL;
	}
}

<COMMAND>{
	"*/"                  { yyless(0); yylloc->last_column = yylloc->first_column; BEGIN(INITIAL); }
	[^*\n]+               { ECHO; yymore(); yylloc->last_column = yylloc->first_column; }
	"*"                   { ECHO; yymore(); yylloc->last_column = yylloc->first_column; }
	\n                    { ECHO; yymore(); yylloc->last_column = yylloc->first_column; }
	<<EOF>>               {
		if(parser) {
			parser->internal_add_error("Unterminated /*! command");
		}

		BEGIN(INITIAL);
		return YY_NULL;
	}
}

<SQSTRING>{
	[^'\\]+               { *(yylval_param->str_val) += yytext; }
	"\\'"                 { *(yylval_param->str_val) += "'"; }
	"\\\\"                { *(yylval_param->str_val) += "\\"; }
	/* Add other standard SQL escape sequences if needed e.g. \n, \t, \b, \r, \0, \Z */
	"\\n"                 { *(yylval_param->str_val) += "\n"; }
	"\\t"                 { *(yylval_param->str_val) += "\t"; }
	"\\r"                 { *(yylval_param->str_val) += "\r"; }
	"\\b"                 { *(yylval_param->str_val) += "\b"; }
	"\\0"                 { *(yylval_param->str_val) += "\0"; }
	"\\Z"                 { *(yylval_param->str_val) += "\x1a"; } /* Ctrl+Z */
	"''"                  { *(yylval_param->str_val) += "'"; } /* SQL standard for literal single quote */
	"'"                   {
		*(yylval_param->str_val) += "'";
		yylloc->first_column -= yylval_param->str_val->size() - 1;
		BEGIN(INITIAL);
		return TOKEN_STRING_LITERAL;
	}
	<<EOF>>               {
		if (parser) {
			parser->internal_add_error("Unterminated single-quoted string");
		}

		BEGIN(INITIAL);
		return YY_NULL;
	}
}

<DQSTRING>{
	[^"\\]+               { *(yylval_param->str_val) += yytext; }
	"\\\""                { *(yylval_param->str_val) += "\""; }
	"\\\\"                { *(yylval_param->str_val) += "\\"; }
	/* Add other standard SQL escape sequences if needed */
	"\\n"                 { *(yylval_param->str_val) += "\n"; }
	"\\t"                 { *(yylval_param->str_val) += "\t"; }
	"\\r"                 { *(yylval_param->str_val) += "\r"; }
	"\\b"                 { *(yylval_param->str_val) += "\b"; }
	"\\0"                 { *(yylval_param->str_val) += "\0"; }
	"\\Z"                 { *(yylval_param->str_val) += "\x1a"; }
	"\"\""                { *(yylval_param->str_val) += "\""; } /* SQL standard for literal double quote */
	"\""                  {
		*(yylval_param->str_val) += "\"";
		yylloc->first_column -= yylval_param->str_val->size() - 1;
		BEGIN(INITIAL);
		return TOKEN_STRING_LITERAL;
	}
	<<EOF>>               {
		if (parser) {
			parser->internal_add_error("Unterminated double-quoted string");
		}

		BEGIN(INITIAL);
		return YY_NULL;
	}
}

<BTIDENT>{
	[^`\n]+               { *(yylval_param->str_val) += yytext; }
	"``"                  { *(yylval_param->str_val) += '`'; } /* Escaped backtick inside identifier */
	"`"                   {
		*(yylval_param->str_val) += "`";
		yylloc->first_column -= yylval_param->str_val->size() - 1;
		BEGIN(INITIAL);

		return TOKEN_IDENTIFIER;
	}
	\n                    {
		/* Error, but return to INITIAL */
		if (parser) {
			parser->internal_add_error("Newline in backticked identifier");
		}

		BEGIN(INITIAL);
	}
	<<EOF>>               {
		if (parser) {
			parser->internal_add_error("Unterminated backticked identifier");
		}

		BEGIN(INITIAL);
		return YY_NULL;
	}
}

%%
/* C code to be included at the end of the lexer */

