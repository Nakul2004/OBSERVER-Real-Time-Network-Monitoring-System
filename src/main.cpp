
#include <crow.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <fstream>
#include <sstream>

#include "Analyzer.h"
#include "Database.h"

// Set the directory where frontend files should be located relative to the executable
const std::string FRONTEND_DIR = "frontend/";

// Helper function to load a static file from disk
crow::response load_static_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) {
        return crow::response(404, "File Not Found");
    }
    std::ostringstream ss;
    ss << in.rdbuf();

    auto ends_with = [](const std::string& str, const std::string& suffix) {
        if (str.length() < suffix.length()) {
            return false;
        }
        return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
    };

    crow::response res(ss.str());
    if (ends_with(path, ".html")) {
        res.set_header("Content-Type", "text/html");
    }
    else if (ends_with(path, ".js")) {
        res.set_header("Content-Type", "application/javascript");
    }
    else if (ends_with(path, ".css")) {
        res.set_header("Content-Type", "text/css");
    }
    return res;
}

int main() {
    // Initialize DB
    if (!DBManager::get().initialize()) {
        std::cerr << "Failed to initialize database" << std::endl;
        return 1;
    }

    Analyzer analyzer;

    std::string device_to_sniff = analyzer.find_and_select_adapter();

    if (device_to_sniff.empty()) {
        std::cerr << "Failed to find a suitable network adapter. Cannot start sniffing." << std::endl;
        // Continue running the server for non-sniffing endpoints, but traffic analysis won't work.
        // You might want to return 1 here if sniffing is mandatory.
    }
    else {
        // 2b. Start sniffing on the selected device
        // Start sniffing with BPF filter "ip" to capture all IPv4 traffic
        if (!analyzer.start_sniffing(device_to_sniff, "ip")) {
            std::cerr << "Failed to start packet sniffing on selected device: " << device_to_sniff << ". Check device privileges (run as Admin) and Npcap installation." << std::endl;
        }
    }
   /* // Start sniffing for all IP traffic
    if (!analyzer.start_sniffing("ip")) {
        std::cerr << "Failed to start network sniffing. Check Npcap installation and Administrator rights." << std::endl;
        // Exit gracefully if sniffing fails, as the core function won't work
        return 1;
    }   */

    crow::SimpleApp app;

    // Mutex and set to manage all connected WebSocket clients
    std::mutex clientsMutex;
    std::set<crow::websocket::connection*> clients;

    // Redirect root path to the dashboard
    CROW_ROUTE(app, "/")([&]() {
        crow::response res;
        res.set_header("Location", "/frontend/index.html");
        res.code = 302;
        return res;
        });

    // Route to serve static frontend files
    CROW_ROUTE(app, "/frontend/<string>")([&](const crow::request& req, const std::string& file) {
        (void)req; // silence unused warning
        return load_static_file(FRONTEND_DIR + file);
        });

    // WebSocket endpoint for real-time data
    CROW_ROUTE(app, "/ws")
        .websocket(&app)
        .onopen([&](crow::websocket::connection& conn) {
        std::lock_guard<std::mutex> g(clientsMutex);
        clients.insert(&conn);
            })
        .onclose([&](crow::websocket::connection& conn, const std::string& reason, uint16_t close_code) {
        (void)close_code;
            std::lock_guard<std::mutex> g(clientsMutex);
        clients.erase(&conn);
        std::cout << "WS closed: " << reason << std::endl;
            })
        .onmessage([&](crow::websocket::connection& /*conn*/, const std::string& /*data*/, bool /*is_binary*/) {
        // Server doesn't process incoming WS messages, only sends them
            });

    // Admin route to retrieve all logged packet data (as JSON)
    CROW_ROUTE(app, "/admin/logs")([&]() {
        // Retrieve and dump the JSON array of logs
        return crow::response(DBManager::get().get_all_logs().dump(4));
        });


    // Background broadcaster thread
    std::atomic<bool> running{ true };
    std::thread broadcaster([&]() {
        const int windowSeconds = 3; // Update interval
        while (running.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(windowSeconds));

            // 1. Get snapshot and reset counters
            auto snapshot = analyzer.build_and_reset_snapshot_json(windowSeconds);
            const std::string payload = snapshot.dump();

            // 2. Broadcast to all clients
            std::lock_guard<std::mutex> g(clientsMutex);
            for (auto* c : clients) {
                if (c) {
                    try {
                        c->send_text(payload);
                    }
                    catch (const std::exception& e) {
                        std::cerr << "WS send error: " << e.what() << std::endl;
                        // Client will be cleaned up on next onclose event
                    }
                }
            }
        }
        });

    // Start the Crow server
    std::cout << "TrafficAnalyzer listening on http://localhost:8080\n";
    app.port(8080).multithreaded().run();

    // Cleanup: Stop background threads and analyzer when Crow server shuts down
    running = false;
    if (broadcaster.joinable()) {
        broadcaster.join();
    }
    analyzer.stop_sniffing();

    return 0;
}


