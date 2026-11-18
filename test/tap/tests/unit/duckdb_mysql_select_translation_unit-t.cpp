#include "duckdb.h"
#include "duckdb_mysql_select_compat.h"
#include "tap.h"
#include <limits>
#include <string>
#include <vector>

int main() {
    plan(NO_PLAN);
    DuckDBMySQLSelectContext context;
    size_t calls = 0;
    context.resolve_relation = [&](const std::vector<std::string> &parts,
                                   DuckDBMySQLRelation &out) {
        ++calls;
        if (parts != std::vector<std::string>{"odd`table"})
            return false;
        out.canonical_name = {"odd`table"};
        out.exact_name_resolution = true;
        out.columns = {{"id", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                       {"a`b", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                       {"txt", {DuckDBMySQLTypeKind::text, 0, 0}},
                       {"u", {DuckDBMySQLTypeKind::unsigned_integer, 0, 0}},
                       {"tiny", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                       {"d", {DuckDBMySQLTypeKind::exact_decimal, 18, 4}},
                       {"fraction", {DuckDBMySQLTypeKind::exact_decimal, 38, 30}},
                       {"wide", {DuckDBMySQLTypeKind::exact_decimal, 38, 0}},
                       {"invalid_decimal", {DuckDBMySQLTypeKind::exact_decimal, 40, 0}},
                       {"huge", {DuckDBMySQLTypeKind::exact_decimal, 39, 0}},
                       {"fraction_only", {DuckDBMySQLTypeKind::exact_decimal, 2, 2}}};
        out.unique_keys = {{"id"}};
        return true;
    };
    auto result = duckdb_translate_mysql_select(
        "SELECT `a``b`, id AS x, id AS x FROM `odd``table` ORDER BY id LIMIT 2, 3", context);
    ok(result.decision == DuckDBMySQLSelectDecision::supported,
       "backticks and comma limit are admitted");
    ok(result.sql == "SELECT \"a`b\", \"id\" AS \"x\", \"id\" AS \"x\" FROM \"odd`table\" ORDER BY "
                     "\"id\" ASC NULLS FIRST LIMIT 3 OFFSET 2",
       "emission preserves identifiers and aliases");
    ok(calls == 1, "one metadata lookup");
    duckdb_database db = nullptr;
    duckdb_connection connection = nullptr;
    duckdb_result native{};
    bool opened = duckdb_open(nullptr, &db) == DuckDBSuccess &&
                  duckdb_connect(db, &connection) == DuckDBSuccess;
    ok(opened, "open test database");
    bool created = opened && duckdb_query(connection,
                                          "CREATE TABLE \"odd`table\" (id BIGINT, \"a`b\" BIGINT, "
                                          "txt VARCHAR, u UBIGINT, tiny TINYINT, d DECIMAL(18,4), "
                                          "fraction DECIMAL(38,30), wide DECIMAL(38,0))",
                                          &native) == DuckDBSuccess;
    duckdb_destroy_result(&native);
    ok(created, "create test relation");
    duckdb_prepared_statement statement = nullptr;
    ok(created && duckdb_prepare(connection, result.sql.c_str(), &statement) == DuckDBSuccess,
       "DuckDB prepares emitted SQL");
    auto column_name = [&](idx_t index) {
        const char *name = duckdb_prepared_statement_column_name(statement, index);
        std::string value = name ? name : "";
        if (name)
            duckdb_free(const_cast<char *>(name));
        return value;
    };
    ok(statement && column_name(0) == "a`b" && column_name(1) == "x" && column_name(2) == "x",
       "DuckDB preserves duplicate result labels");
    duckdb_destroy_prepare(&statement);
    result = duckdb_translate_mysql_select(
        "SELECT `a``b`, COUNT(*) AS n, MIN(id) AS lo, MAX(id) AS hi FROM `odd``table` GROUP BY "
        "`a``b` HAVING COUNT(*) > 1 AND MIN(id) IS NOT NULL ORDER BY `a``b` LIMIT 1, 2",
        context);
    ok(result.decision == DuckDBMySQLSelectDecision::supported,
       "group, typed aggregates and HAVING admitted");
    ok(result.sql.find("GROUP BY \"a`b\" HAVING") != std::string::npos &&
           result.sql.find("NULLS FIRST LIMIT 2 OFFSET 1") != std::string::npos,
       "grouping, HAVING and deterministic comma LIMIT rendered");
    statement = nullptr;
    ok(created && result.decision == DuckDBMySQLSelectDecision::supported &&
           duckdb_prepare(connection, result.sql.c_str(), &statement) == DuckDBSuccess,
       "DuckDB prepares translated grouped SQL");
    duckdb_destroy_prepare(&statement);
    auto decimals = duckdb_translate_mysql_select(
        "SELECT 001.2300,.50,1. FROM `odd``table` WHERE d = 1.0", context);
    ok(decimals.decision == DuckDBMySQLSelectDecision::supported,
       "decimal literals and exact comparison admitted");
    ok(decimals.sql.find("CAST('001.2300' AS DECIMAL(7,4)) AS \"001.2300\"") != std::string::npos,
       "decimal token emitted losslessly with original label");
    statement = nullptr;
    ok(created && decimals.decision == DuckDBMySQLSelectDecision::supported &&
           duckdb_prepare(connection, decimals.sql.c_str(), &statement) == DuckDBSuccess,
       "DuckDB prepares translated exact decimals");
    duckdb_destroy_prepare(&statement);
    auto prepare_context = context;
    prepare_context.parameter_mode = DuckDBMySQLParameterMode::prepare;
    const std::string parameter_sql = "SELECT id FROM `odd``table` WHERE tiny = ?";
    auto parameter_result = duckdb_translate_mysql_select(parameter_sql, prepare_context);
    ok(parameter_result.decision == DuckDBMySQLSelectDecision::supported &&
           parameter_result.parameter_count == 1,
       "prepare mode admits signed integer predicate parameter");
    ok(parameter_result.sql.find("CAST(\"tiny\" AS BIGINT) = CAST(? AS BIGINT)") !=
           std::string::npos,
       "signed column and placeholder use explicit BIGINT casts");
    statement = nullptr;
    bool prepared_param =
        created && parameter_result.decision == DuckDBMySQLSelectDecision::supported &&
        duckdb_prepare(connection, parameter_result.sql.c_str(), &statement) == DuckDBSuccess;
    ok(prepared_param && duckdb_nparams(statement) == 1 &&
           duckdb_param_type(statement, 1) == DUCKDB_TYPE_BIGINT,
       "DuckDB prepares one BIGINT parameter");
    duckdb_result param_rows{};
    if (created) {
        duckdb_query(connection, "INSERT INTO \"odd`table\" (id,tiny) VALUES (1,5),(2,6)",
                     &param_rows);
        duckdb_destroy_result(&param_rows);
    }
    auto execute_bound = [&](int64_t value, bool is_null) -> idx_t {
        if (!statement)
            return 999;
        duckdb_clear_bindings(statement);
        if ((is_null ? duckdb_bind_null(statement, 1) : duckdb_bind_int64(statement, 1, value)) !=
            DuckDBSuccess)
            return 999;
        duckdb_result rows{};
        if (duckdb_execute_prepared(statement, &rows) != DuckDBSuccess) {
            duckdb_destroy_result(&rows);
            return 999;
        }
        auto count = duckdb_row_count(&rows);
        duckdb_destroy_result(&rows);
        return count;
    };
    ok(prepared_param && execute_bound(5, false) == 1 && execute_bound(6, false) == 1,
       "one native prepared handle supports changing integer values");
    ok(prepared_param && execute_bound(200, false) == 0,
       "out-of-TINYINT-range binding returns zero rows");
    ok(prepared_param && execute_bound(0, true) == 0,
       "NULL bound predicate uses three-valued logic");
    ok(prepared_param && execute_bound(std::numeric_limits<int64_t>::min(), false) == 0 &&
           execute_bound(std::numeric_limits<int64_t>::max(), false) == 0,
       "full signed 64-bit boundary parameters do not narrow");
    duckdb_destroy_prepare(&statement);
    auto multi = duckdb_translate_mysql_select(
        "SELECT id FROM `odd``table` WHERE (? < id AND id <= ?)", prepare_context);
    statement = nullptr;
    bool multi_prepared =
        multi.decision == DuckDBMySQLSelectDecision::supported &&
        duckdb_prepare(connection, multi.sql.c_str(), &statement) == DuckDBSuccess &&
        duckdb_nparams(statement) == 2;
    duckdb_result multi_rows{};
    bool multi_ok = multi_prepared && duckdb_bind_int64(statement, 1, 1) == DuckDBSuccess &&
                    duckdb_bind_int64(statement, 2, 2) == DuckDBSuccess &&
                    duckdb_execute_prepared(statement, &multi_rows) == DuckDBSuccess;
    ok(multi_ok && duckdb_row_count(&multi_rows) == 1 && duckdb_value_int64(&multi_rows, 0, 0) == 2,
       "native binding keeps multiple placeholders in source order");
    duckdb_destroy_result(&multi_rows);
    duckdb_destroy_prepare(&statement);
    if (connection)
        duckdb_disconnect(&connection);
    if (db)
        duckdb_close(&db);
    result = duckdb_translate_mysql_select(
        "SELECT q.id FROM `odd``table` AS q ORDER BY q.id LIMIT 1", context);
    ok(result.decision == DuckDBMySQLSelectDecision::supported,
       "table alias and qualified column admitted");
    ok(result.sql.find("SELECT \"id\"") == 0, "qualified column preserves column output label");
    result = duckdb_translate_mysql_select("SELECT 001, NULL", context);
    ok(result.decision == DuckDBMySQLSelectDecision::supported, "literal SELECT admitted");
    ok(result.sql == "SELECT 001 AS \"001\", NULL AS \"NULL\"", "literal output labels preserved");
    auto refused = [&](const char *sql) {
        return duckdb_translate_mysql_select(sql, context).decision !=
               DuckDBMySQLSelectDecision::supported;
    };
    auto admitted = [&](const char *sql) {
        return duckdb_translate_mysql_select(sql, context).decision ==
               DuckDBMySQLSelectDecision::supported;
    };
    ok(admitted("SELECT id,COUNT(*) FROM `odd``table` GROUP BY id"),
       "key and count group admitted");
    ok(admitted("SELECT MIN(id),MAX(id) FROM `odd``table`"),
       "ungrouped signed min and max admitted");
    ok(admitted("SELECT COUNT(*) FROM `odd``table` HAVING COUNT(*) = 0"),
       "empty aggregate HAVING admitted");
    ok(admitted("SELECT id,COUNT(*) FROM `odd``table` GROUP BY id ORDER BY id LIMIT 1"),
       "complete group-key ordering establishes deterministic limit");
    ok(refused("SELECT id,COUNT(*) FROM `odd``table` GROUP BY `a``b`"),
       "non-key group projection refused");
    ok(refused("SELECT txt,COUNT(*) FROM `odd``table` GROUP BY txt"), "text group key refused");
    ok(refused("SELECT id,COUNT(*) FROM `odd``table` GROUP BY id ORDER BY id LIMIT 1,2; SELECT 1"),
       "multi-statement grouping refused");
    ok(refused("SELECT id,COUNT(*) FROM `odd``table` GROUP BY id ORDER BY `a``b` LIMIT 1"),
       "non-key group ordering refused");
    ok(refused("SELECT id,COUNT(*) FROM `odd``table` GROUP BY id LIMIT 1"),
       "unordered group limit refused");
    ok(refused("SELECT id AS `a``b`,COUNT(*) FROM `odd``table` GROUP BY `a``b`"),
       "group alias shadowing refused");
    ok(refused("SELECT id,COUNT(*) AS id FROM `odd``table` GROUP BY id"),
       "group key alias ambiguity refused");
    ok(refused("SELECT SUM(id) FROM `odd``table`"), "SUM remains refused");
    ok(refused("SELECT AVG(id) FROM `odd``table`"), "AVG remains refused");
    ok(admitted("SELECT u,MIN(u),MAX(u) FROM `odd``table` GROUP BY u ORDER BY u"),
       "unsigned keys and extrema admitted");
    ok(refused("SELECT MIN(u) FROM `odd``table` HAVING MIN(u) > 1"),
       "unsigned extrema comparison refuses unproven coercion");
    ok(refused("SELECT MIN(id) FROM `odd``table` HAVING MIN(id) > 9223372036854775808"),
       "HAVING literal overflow refused");
    ok(refused("SELECT MIN(txt) FROM `odd``table`"), "text MIN refused");
    ok(refused("SELECT MIN(MAX(id)) FROM `odd``table`"), "nested aggregate refused");
    ok(refused("SELECT COUNT(*) FROM `odd``table` HAVING COUNT(*) > txt"),
       "ambiguous HAVING operand refused");
    ok(refused("SELECT COUNT(*) AS n FROM `odd``table` HAVING n > 1"),
       "HAVING output alias refused");
    ok(refused("SELECT id,COUNT(*) FROM `odd``table` GROUP BY 1"), "group ordinal refused");
    ok(refused("SELECT id,COUNT(*) FROM `odd``table` GROUP BY id WITH ROLLUP"), "ROLLUP refused");
    ok(admitted("SELECT d FROM `odd``table` WHERE d = tiny"),
       "decimal and signed integer comparison admitted");
    ok(admitted("SELECT d FROM `odd``table` WHERE d < u"),
       "decimal and unsigned integer comparison admitted");
    ok(admitted("SELECT fraction FROM `odd``table` WHERE fraction = 1"),
       "scale-30 decimal with small integer literal admitted");
    ok(admitted(
           "SELECT wide FROM `odd``table` WHERE wide = 99999999999999999999999999999999999999"),
       "38-digit integer literal compares exactly to decimal");
    ok(refused("SELECT fraction FROM `odd``table` WHERE fraction = id"),
       "common precision 49 refused");
    ok(refused("SELECT 1e3"), "exponent literal refused");
    ok(refused("SELECT 0.0000000000000000000000000000001"), "decimal scale above 30 refused");
    ok(refused("SELECT 999999999999999999999999999999999999999.0"),
       "decimal precision above 38 refused");
    ok(refused("SELECT d FROM `odd``table` WHERE d = txt"), "decimal text coercion refused");
    ok(refused("SELECT d FROM `odd``table` WHERE d = ?"), "decimal parameter refused by default");
    ok(admitted("SELECT huge FROM `odd``table`"),
       "39-digit native wide integer projection remains available");
    ok(refused("SELECT id FROM `odd``table` WHERE huge = 1.0"),
       "39-digit native integer decimal comparison refused");
    ok(refused("SELECT invalid_decimal FROM `odd``table` WHERE invalid_decimal = 1.0"),
       "invalid native decimal precision refused");
    auto fractional_projection =
        duckdb_translate_mysql_select("SELECT fraction_only FROM `odd``table`", context);
    ok(fractional_projection.decision == DuckDBMySQLSelectDecision::supported &&
           fractional_projection.sql.find(
               "CAST(\"fraction_only\" AS DECIMAL(3,2)) AS \"fraction_only\"") != std::string::npos,
       "fraction-only decimal projection preserves original label");
    auto fractional_context = context;
    fractional_context.resolve_relation = [](const std::vector<std::string> &,
                                             DuckDBMySQLRelation &out) {
        out.canonical_name = {"t"};
        out.exact_name_resolution = true;
        out.columns = {{"only_fraction", {DuckDBMySQLTypeKind::exact_decimal, 2, 2}}};
        return true;
    };
    auto fractional_star = duckdb_translate_mysql_select("SELECT * FROM t", fractional_context);
    ok(fractional_star.decision == DuckDBMySQLSelectDecision::supported &&
           fractional_star.sql.find(
               "CAST(\"only_fraction\" AS DECIMAL(3,2)) AS \"only_fraction\"") != std::string::npos,
       "star expands and normalizes fraction-only decimal");
    auto fractional_alias = duckdb_translate_mysql_select(
        "SELECT fraction_only AS x, fraction_only AS x FROM `odd``table`", context);
    ok(fractional_alias.decision == DuckDBMySQLSelectDecision::supported &&
           fractional_alias.sql.find("CAST(\"fraction_only\" AS DECIMAL(3,2)) AS \"x\", "
                                     "CAST(\"fraction_only\" AS DECIMAL(3,2)) AS \"x\"") !=
               std::string::npos,
       "fraction-only casts preserve duplicate explicit aliases");
    auto fractional_and_wide = fractional_context;
    fractional_and_wide.resolve_relation = [](const std::vector<std::string> &,
                                              DuckDBMySQLRelation &out) {
        out.canonical_name = {"t"};
        out.exact_name_resolution = true;
        out.columns = {{"frac", {DuckDBMySQLTypeKind::exact_decimal, 2, 2}},
                       {"wide", {DuckDBMySQLTypeKind::exact_decimal, 39, 0}}};
        return true;
    };
    auto mixed_star = duckdb_translate_mysql_select("SELECT * FROM t", fractional_and_wide);
    ok(mixed_star.decision == DuckDBMySQLSelectDecision::supported &&
           mixed_star.sql.find("CAST(\"frac\" AS DECIMAL(3,2)) AS \"frac\", \"wide\"") !=
               std::string::npos,
       "expanded star preserves wide integer projection");
    auto fractional_ambiguous = fractional_context;
    fractional_ambiguous.resolve_relation = [](const std::vector<std::string> &,
                                               DuckDBMySQLRelation &out) {
        out.canonical_name = {"t"};
        out.exact_name_resolution = true;
        out.columns = {{"v", {DuckDBMySQLTypeKind::exact_decimal, 2, 2}},
                       {"V", {DuckDBMySQLTypeKind::signed_integer, 0, 0}}};
        return true;
    };
    ok(duckdb_translate_mysql_select("SELECT * FROM t", fractional_ambiguous).decision !=
           DuckDBMySQLSelectDecision::supported,
       "star expansion refuses ambiguous native names");
    auto fractional_output_bound = fractional_context;
    fractional_output_bound.max_output_bytes = 20;
    ok(duckdb_translate_mysql_select("SELECT * FROM t", fractional_output_bound).reason ==
           "resource_limit",
       "expanded star observes output bound");
    ok(admitted("SELECT id FROM `odd``table` WHERE fraction_only = .50"),
       "fraction-only decimal comparison admitted");
    ok(refused("SELECT MIN(d) FROM `odd``table`"), "decimal MIN remains refused");
    auto prep = context;
    prep.parameter_mode = DuckDBMySQLParameterMode::prepare;
    ok(duckdb_translate_mysql_select("SELECT d FROM `odd``table` WHERE d = ?", prep).decision !=
           DuckDBMySQLSelectDecision::supported,
       "decimal parameter remains refused even in prepare mode");
    auto execute = context;
    execute.parameter_mode = DuckDBMySQLParameterMode::execute;
    execute.parameter_kinds = {DuckDBMySQLParameterKind::signed_integer,
                               DuckDBMySQLParameterKind::null_value};
    const std::string two = "SELECT id FROM `odd``table` WHERE (? < id AND id <= ?)";
    auto translated = duckdb_translate_mysql_select(two, execute);
    ok(translated.decision == DuckDBMySQLSelectDecision::supported &&
           translated.parameter_count == 2 &&
           translated.sql.find("CAST(? AS BIGINT) < CAST(\"id\" AS BIGINT)") != std::string::npos,
       "two placeholders retain reversed source order and accept NULL kind");
    execute.parameter_kinds = {DuckDBMySQLParameterKind::unsupported,
                               DuckDBMySQLParameterKind::null_value};
    ok(duckdb_translate_mysql_select(two, execute).reason == "unsupported_parameter_type",
       "unsupported bound kind rejected");
    execute.parameter_kinds = {DuckDBMySQLParameterKind::signed_integer};
    ok(duckdb_translate_mysql_select(two, execute).reason == "parameter_count_mismatch",
       "bound count mismatch rejected");
    execute.parameter_kinds = {DuckDBMySQLParameterKind::signed_integer,
                               DuckDBMySQLParameterKind::null_value};
    ok(duckdb_translate_mysql_select(two, execute).decision == DuckDBMySQLSelectDecision::supported,
       "valid bound types recover after rejection");
    ok(refused("SELECT id FROM `odd``table` WHERE id = ?"),
       "default COM_QUERY forbids placeholders");
    for (const char *sql :
         {"SELECT ?", "SELECT id FROM `odd``table` ORDER BY ?",
          "SELECT id FROM `odd``table` LIMIT ?",
          "SELECT COUNT(*) FROM `odd``table` HAVING COUNT(*) > ?",
          "SELECT id FROM `odd``table` WHERE txt = ?", "SELECT id FROM `odd``table` WHERE u = ?",
          "SELECT id FROM `odd``table` WHERE ? = ?"})
        ok(duckdb_translate_mysql_select(sql, prep).decision !=
               DuckDBMySQLSelectDecision::supported,
           "unsupported parameter placement refused: %s", sql);
    auto too_many_facts = execute;
    too_many_facts.parameter_kinds.assign(257, DuckDBMySQLParameterKind::signed_integer);
    ok(duckdb_translate_mysql_select(two, too_many_facts).reason == "resource_limit",
       "parameter fact vector has a hard limit before copying");
    auto invalid_mode = context;
    invalid_mode.parameter_mode = static_cast<DuckDBMySQLParameterMode>(255);
    ok(duckdb_translate_mysql_select("SELECT 1", invalid_mode).reason == "invalid_parameter_mode",
       "invalid parameter mode refused");
    auto invalid_kind = execute;
    invalid_kind.parameter_kinds = {static_cast<DuckDBMySQLParameterKind>(255),
                                    DuckDBMySQLParameterKind::null_value};
    auto invalid_result = duckdb_translate_mysql_select(two, invalid_kind);
    ok(invalid_result.reason == "unsupported_parameter_type" && invalid_result.sql.empty(),
       "unknown bound kind refused without SQL");
    std::function<std::string(size_t)> balanced = [&](size_t n) -> std::string {
        if (n == 1)
            return "id = ?";
        const size_t left = n / 2;
        return "(" + balanced(left) + " OR " + balanced(n - left) + ")";
    };
    const std::string prefix = "SELECT id FROM `odd``table` WHERE ";
    auto max_result = duckdb_translate_mysql_select(prefix + balanced(256), prep);
    ok(max_result.decision == DuckDBMySQLSelectDecision::supported &&
           max_result.parameter_count == 256,
       "256 balanced placeholders are admitted");
    auto oversized_result = duckdb_translate_mysql_select(prefix + balanced(257), prep);
    ok(oversized_result.reason == "resource_limit" && oversized_result.sql.empty(),
       "257 balanced placeholders hit the parameter limit");
    auto mixed = duckdb_translate_mysql_select("SELECT ? FROM `odd``table` WHERE id = ?", prep);
    ok(mixed.decision != DuckDBMySQLSelectDecision::supported && mixed.sql.empty(),
       "unconsumed earlier parameter refuses whole query");
    auto same_sql = duckdb_translate_mysql_select(two, prep);
    ok(same_sql.decision == DuckDBMySQLSelectDecision::supported && same_sql.sql == translated.sql,
       "prepare and execute emit identical SQL and placeholder order");
    ok(duckdb_translate_mysql_select("SELECT COUNT(*) FROM `odd``table` GROUP BY ?", prep)
               .decision != DuckDBMySQLSelectDecision::supported,
       "GROUP BY placeholder refused");
    auto forbidden_facts = prep;
    forbidden_facts.parameter_kinds = {DuckDBMySQLParameterKind::null_value};
    ok(duckdb_translate_mysql_select("SELECT 1", forbidden_facts).reason ==
           "parameter_count_mismatch",
       "prepare mode rejects bound facts");
    size_t before = calls;
    ok(refused("SELECT nextval('x')"), "side-effect function refused");
    ok(calls == before, "function analysis invokes no resolver or execution");
    ok(refused("SELECT @x"), "user variable refused");
    ok(refused("SELECT @@version"), "system variable refused");
    ok(refused("SELECT 1;;"), "extra empty statement refused");
    ok(refused("SELECT 1; SELECT 2"), "multiple statements refused");
    ok(refused("SELECT 1 /*! + 1 */"), "executable comment refused");
    ok(duckdb_translate_mysql_select("SELECT COUNT(*) FROM `odd``table`", context).decision ==
           DuckDBMySQLSelectDecision::supported,
       "count star admitted");
    ok(refused("SELECT COUNT(*), id FROM `odd``table`"),
       "mixed aggregate and plain columns refused");
    ok(refused("SELECT 1 + 2"), "arithmetic refused");
    ok(refused("SELECT 9223372036854775808"), "overflow literal refused");
    ok(refused("SELECT id FROM `odd``table` LIMIT 1"), "unordered limit refused");
    ok(refused("SELECT id FROM `odd``table` ORDER BY txt"),
       "text ordering refused without collation");
    ok(refused("SELECT id FROM `odd``table` WHERE txt = 'x'"), "text comparison refused");
    result = duckdb_translate_mysql_select(
        "SELECT id FROM `odd``table` WHERE id = 2 ORDER BY id DESC LIMIT 1", context);
    ok(result.decision == DuckDBMySQLSelectDecision::supported &&
           result.sql.find("DESC NULLS LAST") != std::string::npos,
       "integer comparison and MySQL null ordering admitted");
    result = duckdb_translate_mysql_select("SELECT null, NuLl", context);
    ok(result.decision == DuckDBMySQLSelectDecision::supported &&
           result.sql == "SELECT NULL AS \"NULL\", NULL AS \"NULL\"",
       "NULL expression labels use MySQL canonical case");
    std::string alias256(256, 'a');
    ok(admitted(("SELECT 1 AS `" + alias256 + "`").c_str()), "256-byte alias is preserved");
    ok(refused(("SELECT 1 AS `" + alias256 + "a`").c_str()), "alias truncation boundary refused");
    ok(refused("SELECT 1 AS `x😀y`"), "supplementary metadata characters refused");
    ok(refused("SELECT 1 AS ` x`"), "leading alias whitespace refused");
    ok(admitted("SELECT 1 AS `x `"), "trailing alias whitespace preserved");
    std::string bmp;
    for (size_t i = 0; i < 128; ++i)
        bmp += "é";
    ok(admitted(("SELECT 1 AS `" + bmp + "`").c_str()), "256-byte BMP alias preserved");
    ok(refused(("SELECT 1 AS `" + bmp + "é`").c_str()), "BMP byte-length overflow refused");
    ok(admitted(("SELECT COUNT(" + std::string(247, ' ') + "*)").c_str()),
       "255-byte aggregate label preserved");
    ok(refused(("SELECT COUNT(" + std::string(248, ' ') + "*)").c_str()),
       "aggregate label truncation boundary refused");
    ok(admitted(("SELECT " + std::string(300, '0') + "1").c_str()),
       "long integral literal labels remain supported");
    ok(refused("SELECT COUNT (*)"), "spaced COUNT requires unknown IGNORE_SPACE mode");
    ok(refused("SELECT MIN (id) FROM `odd``table`"), "spaced MIN cannot be treated as builtin");
    ok(refused("SELECT MAX\t(id) FROM `odd``table`"),
       "tab-separated MAX cannot be treated as builtin");
    ok(refused("SELECT COUNT(*) FROM `odd``table` HAVING COUNT (*) > 0"),
       "HAVING enforces the same function-resolution rule");
    ok(refused("SELECT `COUNT`(*)"), "quoted function name is not an admitted builtin");
    ok(admitted("SELECT cOuNt(*)"), "contiguous builtin remains case-insensitive");
    auto bounded_group = context;
    bounded_group.max_output_bytes = 24;
    ok(duckdb_translate_mysql_select("SELECT id,COUNT(*) FROM `odd``table` GROUP BY id",
                                     bounded_group)
               .reason == "resource_limit",
       "grouped output remains bounded");
    auto bounded = context;
    bounded.max_nodes = 2;
    ok(duckdb_translate_mysql_select("SELECT 1", bounded).reason == "resource_limit",
       "node bound enforced");
    bounded = context;
    bounded.max_input_bytes = 3;
    ok(duckdb_translate_mysql_select("SELECT 1", bounded).reason == "resource_limit",
       "input bound enforced");
    bounded = context;
    bounded.max_output_bytes = 2;
    ok(duckdb_translate_mysql_select("SELECT 1", bounded).reason == "resource_limit",
       "output bound enforced");
    ok(refused("SELECT `a``b` AS id FROM `odd``table` ORDER BY id"),
       "ambiguous ORDER BY alias refused");
    ok(refused("SELECT id AS \"x\" FROM `odd``table`"),
       "double-quoted alias refused with unknown mode");
    auto unknown = context;
    unknown.resolve_relation = [](const std::vector<std::string> &, DuckDBMySQLRelation &out) {
        out.canonical_name = {"t"};
        out.exact_name_resolution = true;
        out.columns = {{"x", {DuckDBMySQLTypeKind::unknown, 0, 0}}};
        return true;
    };
    ok(duckdb_translate_mysql_select("SELECT x FROM t", unknown).decision ==
           DuckDBMySQLSelectDecision::unsupported,
       "unknown projection type refused");
    ok(duckdb_translate_mysql_select("SELECT * FROM t", unknown).decision ==
           DuckDBMySQLSelectDecision::unsupported,
       "star with unknown type refused");
    unknown.resolve_relation = [](const std::vector<std::string> &, DuckDBMySQLRelation &) -> bool {
        throw 1;
    };
    ok(duckdb_translate_mysql_select("SELECT x FROM t", unknown).reason == "provider_failure",
       "resolver exception is contained");
    bounded = context;
    bounded.max_input_bytes = 999999;
    ok(duckdb_translate_mysql_select(std::string(65537, 'x'), bounded).reason == "resource_limit",
       "implementation hard input cap cannot be raised");
    bounded = context;
    bounded.max_depth = 1;
    ok(duckdb_translate_mysql_select("SELECT 1", bounded).reason == "resource_limit",
       "AST depth bound enforced");
    bounded = context;
    bounded.max_resolver_calls = 0;
    ok(duckdb_translate_mysql_select("SELECT id FROM `odd``table`", bounded).reason ==
           "missing_context",
       "resolver bound enforced");
    return exit_status();
}
