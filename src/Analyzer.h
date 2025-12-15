
#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>

#include <pcap.h>
#include <nlohmann/json.hpp>

// Structure to hold aggregated traffic data
struct TrafficAggregator {
    std::mutex mutex;
    std::map<std::string, uint64_t> bytesByIp;      // Bytes exchanged with each IP address
    std::map<std::string, uint64_t> bytesByProtocol; // Bytes per protocol (TCP, UDP, etc.)
    uint64_t totalBytesSinceReset = 0;             // Total bytes captured in the last window
};

class Analyzer {
public:
    Analyzer();
    ~Analyzer();

    // 1. New method: Finds the most suitable active interface (Ethernet or Wi-Fi).
    std::string find_and_select_adapter();
    
    bool start_sniffing(const std::string& deviceName, const std::string& bpfFilter = "ip");
    void stop_sniffing();

   /* // Starts the packet sniffing loop in a separate thread
    bool start_sniffing(const std::string& bpfFilter = "ip");
    // Stops the sniffing thread
    void stop_sniffing(); */

    // Builds a JSON snapshot of the current state and resets the internal counters
    nlohmann::json build_and_reset_snapshot_json(int windowSeconds);

private:
    // Callback function used by pcap_loop to process each packet
    static void packet_handler(u_char* user,
        const struct pcap_pkthdr* header,
        const u_char* packet);
    std::condition_variable init_cv_;
    std::mutex init_mutex_;
    bool initialization_finished_ = false;

    // Main thread function that runs the sniffing loop
    void run_loop(const std::string& bpfFilter);

    // Helpers
    static std::string protocol_to_string(uint8_t proto);

    std::thread captureThread;
    std::atomic<bool> running{ false };
    pcap_t* pcapHandle{ nullptr }; // Npcap device handle

    TrafficAggregator aggregator_;
};


