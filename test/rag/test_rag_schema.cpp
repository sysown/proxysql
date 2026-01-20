/**
 * @file test_rag_schema.cpp
 * @brief Test RAG database schema creation
 *
 * Simple test to verify that RAG tables are created correctly in the vector database.
 */

#include "sqlite3.h"
#include <iostream>
#include <vector>
#include <string>

// List of expected RAG tables
const std::vector<std::string> RAG_TABLES = {
    "rag_sources",
    "rag_documents",
    "rag_chunks",
    "rag_fts_chunks",
    "rag_vec_chunks",
    "rag_sync_state"
};

// List of expected RAG views
const std::vector<std::string> RAG_VIEWS = {
    "rag_chunk_view"
};

static int callback(void *data, int argc, char **argv, char **azColName) {
    int *count = (int*)data;
    (*count)++;
    return 0;
}

int main() {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;

    // Open the default vector database path
    const char* db_path = "/var/lib/proxysql/ai_features.db";
    std::cout << "Testing RAG schema in database: " << db_path << std::endl;

    // Try to open the database
    rc = sqlite3_open(db_path, &db);
    if (rc) {
        std::cerr << "ERROR: Can't open database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }

    std::cout << "SUCCESS: Database opened successfully" << std::endl;

    // Check if RAG tables exist
    bool all_tables_exist = true;
    for (const std::string& table_name : RAG_TABLES) {
        std::string query = "SELECT name FROM sqlite_master WHERE type='table' AND name='" + table_name + "'";
        int count = 0;
        rc = sqlite3_exec(db, query.c_str(), callback, &count, &zErrMsg);

        if (rc != SQLITE_OK) {
            std::cerr << "ERROR: SQL error: " << zErrMsg << std::endl;
            sqlite3_free(zErrMsg);
            all_tables_exist = false;
        } else if (count == 0) {
            std::cerr << "ERROR: Table '" << table_name << "' does not exist" << std::endl;
            all_tables_exist = false;
        } else {
            std::cout << "SUCCESS: Table '" << table_name << "' exists" << std::endl;
        }
    }

    // Check if RAG views exist
    bool all_views_exist = true;
    for (const std::string& view_name : RAG_VIEWS) {
        std::string query = "SELECT name FROM sqlite_master WHERE type='view' AND name='" + view_name + "'";
        int count = 0;
        rc = sqlite3_exec(db, query.c_str(), callback, &count, &zErrMsg);

        if (rc != SQLITE_OK) {
            std::cerr << "ERROR: SQL error: " << zErrMsg << std::endl;
            sqlite3_free(zErrMsg);
            all_views_exist = false;
        } else if (count == 0) {
            std::cerr << "ERROR: View '" << view_name << "' does not exist" << std::endl;
            all_views_exist = false;
        } else {
            std::cout << "SUCCESS: View '" << view_name << "' exists" << std::endl;
        }
    }

    // Clean up
    sqlite3_close(db);

    // Final result
    if (all_tables_exist && all_views_exist) {
        std::cout << "SUCCESS: All RAG schema objects exist" << std::endl;
        return 0;
    } else {
        std::cerr << "FAILURE: Some RAG schema objects are missing" << std::endl;
        return 1;
    }
}
