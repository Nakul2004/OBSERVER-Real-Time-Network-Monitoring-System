
#pragma once

#include <mutex>
#include <string>

#include <sqlite3.h>
#include <nlohmann/json.hpp>

class DBManager {
public:
    // Singleton access pattern
    static DBManager& get();

    // Opens or creates the SQLite database file and ensures the schema is present
    bool initialize(const std::string& dbPath = "traffic_analyzer.db");

    // Logs a single packet detail to the database
    void log_packet_detail(const std::string& timestamp, \
        const std::string& srcIp, \
        const std::string& dstIp, \
        const std::string& protocol, \
        int length, \
        const std::string& userAgent);

    // Retrieves all logged packets as a JSON array
    nlohmann::json get_all_logs();

private:
    DBManager() = default;
    ~DBManager();
    DBManager(const DBManager&) = delete;
    DBManager& operator=(const DBManager&) = delete;

    // Internal function to create the table if it doesn't exist
    bool ensure_schema_locked();

    sqlite3* dbHandle{ nullptr };
    std::mutex dbMutex;
    bool schemaReady{ false };
};


