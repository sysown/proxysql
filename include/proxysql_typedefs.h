#ifndef PROXYSQL_COMMON_TYPEDEF
#define PROXYSQL_COMMON_TYPEDEF
typedef std::unordered_map<std::uint64_t, void *> umap_query_digest;
typedef std::unordered_map<std::uint64_t, char *> umap_query_digest_text;
#endif // PROXYSQL_COMMON_TYPEDEF
