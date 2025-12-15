
#include "Database.h"

#include <chrono>
#include <iostream>
#include <iomanip> // For std::put_time

DBManager & DBManager::get() {
    static DBManager instance;
    return instance;
}

DBManager::~DBManager() {
    // Ensure the database connection is closed safely
    std::lock_guard<std::mutex> lock(dbMutex);
    if (dbHandle) {
        sqlite3_close(dbHandle);
        dbHandle = nullptr;
    }
}

bool DBManager::initialize(const std::string& dbPath) {
    std::lock_guard<std::mutex> lock(dbMutex);
    if (dbHandle) {
        return true;
    }

    // Attempt to open the database file
    if (sqlite3_open(dbPath.c_str(), &dbHandle) != SQLITE_OK) {
        std::cerr << "Failed to open SQLite DB: " << sqlite3_errmsg(dbHandle) << std::endl;
        return false;
    }

    schemaReady = false;
    // Ensure table structure exists
    return ensure_schema_locked();
}

bool DBManager::ensure_schema_locked() {
    if (schemaReady) return true;

    const char* createSql =
        "CREATE TABLE IF NOT EXISTS PACKET_LOGS ("
        "timestamp TEXT,"
        "src_ip TEXT,"
        "dst_ip TEXT,"
        "protocol TEXT,"
        "length INTEGER,"
        "user_agent TEXT"
        ");";

    char* errMsg = nullptr;
    int rc = sqlite3_exec(dbHandle, createSql, nullptr, nullptr, &errMsg);

    if (rc != SQLITE_OK) {
        std::cerr << "SQL error creating table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    schemaReady = true;
    return true;
}

void DBManager::log_packet_detail(const std::string& timestamp,
    const std::string& srcIp,
    const std::string& dstIp,
    const std::string& protocol,
    int length,
    const std::string& userAgent)
{
    if (!dbHandle) return;

    std::lock_guard<std::mutex> lock(dbMutex);

    // Using prepared statements for efficiency and safety
    sqlite3_stmt* stmt = nullptr;
    const char* insertSql =
        "INSERT INTO PACKET_LOGS (timestamp, src_ip, dst_ip, protocol, length, user_agent) VALUES (?, ?, ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(dbHandle, insertSql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare insert: " << sqlite3_errmsg(dbHandle) << std::endl;
        return;
    }

    // Bind parameters to the prepared statement
    sqlite3_bind_text(stmt, 1, timestamp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, srcIp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, dstIp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, protocol.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, length);
    sqlite3_bind_text(stmt, 6, userAgent.c_str(), -1, SQLITE_TRANSIENT);

    // Execute the statement
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to execute insert: " << sqlite3_errmsg(dbHandle) << std::endl;
    }

    // Clean up
    sqlite3_finalize(stmt);
}

nlohmann::json DBManager::get_all_logs() {
    nlohmann::json result = nlohmann::json::array();
    if (!dbHandle) return result;

    std::lock_guard<std::mutex> lock(dbMutex);
    const char* query = "SELECT timestamp, src_ip, dst_ip, protocol, length, user_agent FROM PACKET_LOGS ORDER BY timestamp DESC LIMIT 500;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(dbHandle, query, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare select: " << sqlite3_errmsg(dbHandle) << std::endl;
        return result;
    }

    // Loop through results
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        nlohmann::json row;
        // All SQLite columns are read as TEXT for simplicity here
        row["timestamp"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        row["src_ip"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        row["dst_ip"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        row["protocol"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        row["length"] = sqlite3_column_int(stmt, 4);
        row["user_agent"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        result.push_back(std::move(row));
    }

    sqlite3_finalize(stmt);
    return result;
}


