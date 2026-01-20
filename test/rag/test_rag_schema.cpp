/**
 * @file test_rag_schema.cpp
 * @brief Test RAG database schema creation
 *
 * Simple test to verify that RAG tables are created correctly in the vector database.
 */

#include "sqlite3db.h"
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

int main() {
    // Initialize SQLite database
    SQLite3DB* db = new SQLite3DB();

    // Open the default vector database path
    const char* db_path = "/var/lib/proxysql/ai_features.db";
    std::cout << "Testing RAG schema in database: " << db_path << std::endl;

    // Try to open the database
    if (db->open((char*)db_path) != 0) {
        std::cerr << "ERROR: Failed to open database at " << db_path << std::endl;
        delete db;
        return 1;
    }

    std::cout << "SUCCESS: Database opened successfully" << std::endl;

    // Check if RAG tables exist
    bool all_tables_exist = true;
    for (const std::string& table_name : RAG_TABLES) {
        std::string query = "SELECT name FROM sqlite_master WHERE type='table' AND name='" + table_name + "'";
        char* error = nullptr;
        int cols = 0;
        int affected_rows = 0;
        SQLite3_result* result = db->execute_statement(query.c_str(), &error, &cols, &affected_rows);

        if (error) {
            std::cerr << "ERROR: SQL error for table " << table_name << ": " << error << std::endl;
            sqlite3_free(error);
            all_tables_exist = false;
            if (result) delete result;
            continue;
        }

        if (result && result->rows_count() > 0) {
            std::cout << "SUCCESS: Table '" << table_name << "' exists" << std::endl;
        } else {
            std::cerr << "ERROR: Table '" << table_name << "' does not exist" << std::endl;
            all_tables_exist = false;
        }

        if (result) delete result;
    }

    // Check if RAG views exist
    bool all_views_exist = true;
    for (const std::string& view_name : RAG_VIEWS) {
        std::string query = "SELECT name FROM sqlite_master WHERE type='view' AND name='" + view_name + "'";
        char* error = nullptr;
        int cols = 0;
        int affected_rows = 0;
        SQLite3_result* result = db->execute_statement(query.c_str(), &error, &cols, &affected_rows);

        if (error) {
            std::cerr << "ERROR: SQL error for view " << view_name << ": " << error << std::endl;
            sqlite3_free(error);
            all_views_exist = false;
            if (result) delete result;
            continue;
        }

        if (result && result->rows_count() > 0) {
            std::cout << "SUCCESS: View '" << view_name << "' exists" << std::endl;
        } else {
            std::cerr << "ERROR: View '" << view_name << "' does not exist" << std::endl;
            all_views_exist = false;
        }

        if (result) delete result;
    }

    // Clean up
    db->close();
    delete db;

    // Final result
    if (all_tables_exist && all_views_exist) {
        std::cout << std::endl << "SUCCESS: All RAG schema objects exist!" << std::endl;
        return 0;
    } else {
        std::cerr << std::endl << "ERROR: Some RAG schema objects are missing!" << std::endl;
        return 1;
    }
}