
#include "Analyzer.h"
#include "Database.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>


// Helper structures for packet inspection
// Ethernet header (14 bytes)
struct ethernet_header {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type; // Protocol type (e.g., 0x0800 for IPv4)
};

// IPv4 header (without options)
struct ipv4_header {
    uint8_t ver_ihl; // version(4) + header length(4)
    uint8_t tos;
    uint16_t tlen;
    uint16_t identification;
    uint16_t flags_fo;
    uint8_t ttl;
    uint8_t proto; // Protocol (e.g., 6 for TCP, 17 for UDP)
    uint16_t crc;
    uint32_t saddr; // Source IP
    uint32_t daddr; // Destination IP
};

// TCP header (without options)
struct tcp_header {
    uint16_t sport;
    uint16_t dport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t data_off_reserved; // data offset (4) + reserved
    uint8_t flags;
    uint16_t win;
    uint16_t crc;
    uint16_t urgptr;
};

// --- Analyzer Class Implementation ---

Analyzer::Analyzer() = default;
Analyzer::~Analyzer() { stop_sniffing(); }

std::string Analyzer::protocol_to_string(uint8_t proto) {
    switch (proto) {
    case 1: return "ICMP";
    case 6: return "TCP";
    case 17: return "UDP";
    default: return "Other";
    }
}

// Function that handles the raw packet data
void Analyzer::packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    Analyzer* self = reinterpret_cast<Analyzer*>(user);
    TrafficAggregator& agg = self->aggregator_;

    // 1. Basic Aggregation
    {
        std::lock_guard<std::mutex> lock(agg.mutex);
        agg.totalBytesSinceReset += header->len;
    }

    // Check if packet is too small for basic headers
    if (header->len < 14 + sizeof(ipv4_header)) {
        return;
    }

    // 2. Ethernet and IPv4 Parsing
    const ethernet_header* eth_hdr = reinterpret_cast<const ethernet_header*>(packet);
    // Only process IPv4 (Type 0x0800 in network byte order)
    if (ntohs(eth_hdr->type) != 0x0800) {
        return;
    }

    const ipv4_header* ip_hdr = reinterpret_cast<const ipv4_header*>(packet + 14); // 14 bytes Ethernet
    int ip_header_len = (ip_hdr->ver_ihl & 0x0F) * 4;

    if (header->len < 14 + ip_header_len) {
        return;
    }

    // Convert IPs to string
    struct in_addr src_addr;
    src_addr.s_addr = ip_hdr->saddr;
    std::string src_ip = inet_ntoa(src_addr);

    struct in_addr dst_addr;
    dst_addr.s_addr = ip_hdr->daddr;
    std::string dst_ip = inet_ntoa(dst_addr);

    uint8_t protocol_type = ip_hdr->proto;
    std::string protocol_name = protocol_to_string(protocol_type);
    std::string user_agent; // Used for HTTP traffic

    // 3. Protocol-specific checks (For HTTP User-Agent capture on TCP port 80/443)
    if (protocol_type == 6 /* TCP */) {
        const tcp_header* tcp_hdr = reinterpret_cast<const tcp_header*>(packet + 14 + ip_header_len);
        int tcp_header_len = ((tcp_hdr->data_off_reserved & 0xF0) >> 4) * 4;
        int payload_offset = 14 + ip_header_len + tcp_header_len;
        int payload_len = header->len - payload_offset;

        uint16_t sport = ntohs(tcp_hdr->sport);
        uint16_t dport = ntohs(tcp_hdr->dport);

        // Check for common web ports (80 or 443) and sufficient payload
        if ((sport == 80 || dport == 80 || sport == 443 || dport == 443) && payload_len > 0) {
            // Very simple DPI: look for "User-Agent:" in the first 256 bytes of payload
            const char* payload = reinterpret_cast<const char*>(packet + payload_offset);
            int search_len = min(payload_len, 512);

            const char* ua_start = std::search(payload, payload + search_len, "User-Agent:", "User-Agent:" + 11);

            if (ua_start != payload + search_len) {
                ua_start += 11;
                while (*ua_start == ' ' || *ua_start == '\t') ua_start++;
                const char* ua_end = std::find(ua_start, payload + search_len, '\r');
                if (*ua_end == '\r') {
                    user_agent.assign(ua_start, ua_end - ua_start);
                }
            }
        }
    }

    // 4. Thread-Safe Aggregation Update
    {
        std::lock_guard<std::mutex> lock(agg.mutex);
        agg.bytesByIp[src_ip] += header->len;
        agg.bytesByIp[dst_ip] += header->len;
        agg.bytesByProtocol[protocol_name] += header->len;
    }

    // 5. Database Logging
    using namespace std::chrono;
    auto now = system_clock::now();
    // 1. Get total seconds since epoch
    auto seconds_since_epoch = duration_cast<seconds>(now.time_since_epoch()).count();

    // 2. Convert seconds to time_t and get local time struct
    std::time_t tt = static_cast<std::time_t>(seconds_since_epoch);
    std::tm tm_struct = *std::localtime(&tt);

       std::stringstream ss;
    // ss << std::put_time(std::localtime(&ms), "%Y-%m-%dT%H:%M:%S"); // ISO 8601-like timestamp

    // We must include <iomanip> for std::put_time (you already have this)
    ss << std::put_time(&tm_struct, "%Y-%m-%dT%H:%M:%S");

    DBManager::get().log_packet_detail(
        ss.str(),
        src_ip,
        dst_ip,
        protocol_name,
        static_cast<int>(header->len),
        user_agent
    );
}

// Function to run the sniffing loop
void Analyzer::run_loop(const std::string& bpfFilter) {
    // 1. Find a suitable device (simple approach: use the first non-loopback interface)
    pcap_if_t* all_devs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&all_devs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        running = false;
        return;
    }

    pcap_if_t* d = all_devs;
    pcap_if_t* selected_dev = nullptr;

    while (d != nullptr) {
        // Skip loopback or internal devices, try to find an active Ethernet/Wi-Fi interface
        if (d->flags != PCAP_IF_LOOPBACK && (d->addresses != nullptr)) {
            selected_dev = d;
            break;
        }
        d = d->next;
    }

    if (!selected_dev) {
        std::cerr << "No suitable network device found. Ensure Npcap is installed." << std::endl;
        pcap_freealldevs(all_devs);
        running = false;
        {
            std::lock_guard<std::mutex> lock(init_mutex_);
            initialization_finished_ = true;
        }
        init_cv_.notify_one();
        return;
    }

    std::cout << "Using network device: " << selected_dev->description << std::endl;

    // 2. Open the device
    pcapHandle = pcap_open_live(
        selected_dev->name,
        65536,          // Snaplen (max packet size)
        1,              // Promiscuous mode (1: true)
        1000,           // Timeout (1s)
        errbuf
    );

    if (!pcapHandle) {
        std::cerr << "Error opening device: " << selected_dev->name << " - " << errbuf << ". (Requires Admin rights?)" << std::endl;
        pcap_freealldevs(all_devs);
        running = false;
        {
            std::lock_guard<std::mutex> lock(init_mutex_);
            initialization_finished_ = true;
        }
        init_cv_.notify_one();
        return;
    }

    pcap_freealldevs(all_devs);

    // 3. Compile and apply the BPF filter
    bpf_program fp;
    if (pcap_compile(pcapHandle, &fp, bpfFilter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(pcapHandle) << std::endl;
        pcap_close(pcapHandle);
        pcapHandle = nullptr;
        running = false;
        return;
    }

    if (pcap_setfilter(pcapHandle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(pcapHandle) << std::endl;
        pcap_freecode(&fp);
        pcap_close(pcapHandle);
        pcapHandle = nullptr;
        running = false;
        return;
    }
    pcap_freecode(&fp);

    // 4. Start the capture loop
    running = true;
    {
        std::lock_guard<std::mutex> lock(init_mutex_);
        initialization_finished_ = true;
    }
    init_cv_.notify_one();

    // pcap_loop runs until it captures 'cnt' packets (0 means indefinitely), or error/interrupt
    while (running.load()) {
        int res = pcap_loop(pcapHandle, -1, packet_handler, reinterpret_cast<u_char*>(this));

        // pcap_loop returns -1 on error, -2 on interrupt (pcap_breakloop), or 0 on timeout
        if (res == -1) {
            std::cerr << "pcap_loop error: " << pcap_geterr(pcapHandle) << std::endl;
            running = false;
        }
        else if (res == -2) {
            // Interrupted by pcap_breakloop (intentional stop)
            break;
        }
        else if (res == 0) {
            // Timeout/EOR (should not happen with -1 count)
            continue;
        }
    }

    if (pcapHandle) {
        pcap_close(pcapHandle);
        pcapHandle = nullptr;
    }
}

/**
 * @brief Finds the best active network adapter, prioritizing non-loopback.
 * @return The pcap name of the best suitable adapter (e.g., \Device\NPF_{GUID}), or an empty string on failure.
 */
std::string Analyzer::find_and_select_adapter() {
    pcap_if_t* all_devs;
    pcap_if_t* dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    std::string selected_device = "";
    bool found_active_ethernet = false;

    // 1. Retrieve the list of local devices
    if (pcap_findalldevs(&all_devs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return "";
    }

    // 2. Iterate through the devices
    for (dev = all_devs; dev != nullptr; dev = dev->next) {
        // Skip loopback interfaces
        if (dev->flags & PCAP_IF_LOOPBACK) continue;

        // Skip devices without a name (shouldn't happen with Npcap)
        if (!dev->name) continue;

        // Check if the interface has an active IPv4 address assigned (a simple check for 'active' usage)
        bool has_ipv4 = false;
        for (pcap_addr_t* a = dev->addresses; a != nullptr; a = a->next) {
            // Check for IPv4 addresses
            if (a->addr->sa_family == AF_INET && a->addr && a->netmask) {
                // Ignore 0.0.0.0 addresses (usually inactive or placeholder)
                struct sockaddr_in* sin = (struct sockaddr_in*)a->addr;
                if (sin->sin_addr.s_addr != 0) {
                    has_ipv4 = true;
                    break;
                }
            }
        }

        // Only consider devices with an active IPv4 address
        if (has_ipv4) {
            // Priority Check 1: Explicitly check for Ethernet description
            // Note: This relies on the description string, which can vary.
            std::string desc = (dev->description != nullptr) ? dev->description : "";

            // Prioritize interfaces that look like Ethernet or don't explicitly look like Wi-Fi
            // A common Wi-Fi descriptor is 'Wireless' or 'Wi-Fi'. Ethernet is usually 'Ethernet' or 'Adapter'.
            // If the name/description doesn't contain 'Wireless' and it has an IP, select it.
            if (desc.find("Wireless") == std::string::npos &&
                desc.find("Wi-Fi") == std::string::npos &&
                desc.find("Loopback") == std::string::npos) {

                selected_device = dev->name;
                found_active_ethernet = true; // High priority found
                break; // Use the first suitable Ethernet/Active adapter and stop searching
            }

            // Priority Check 2: If we haven't selected an Ethernet-like one yet,
            // or if it is our current best guess, store the Wi-Fi interface.
            if (!found_active_ethernet) {
                // If it contains "Wireless" or "Wi-Fi", it is still active and better than nothing.
                selected_device = dev->name;
            }
        }
    }

    // 3. Clean up the device list
    pcap_freealldevs(all_devs);

    if (selected_device.empty()) {
        std::cerr << "ERROR: Could not find any suitable active Ethernet or Wi-Fi adapter with an assigned IP." << std::endl;
    }
    else {
        std::cout << "SUCCESS: Selected adapter: " << selected_device << " (" << dev->description << ")" << std::endl;
    }

    return selected_device;
}

bool Analyzer::start_sniffing(const std::string& deviceName, const std::string& bpfFilter) {
    if (running.load()) return true;

    {
        std::lock_guard<std::mutex> lock(init_mutex_);
        initialization_finished_ = false;
    }
    // Use async to start the capture loop thread
    captureThread = std::thread(&Analyzer::run_loop, this, bpfFilter);

   /* // Wait briefly for the loop to initialize or fail
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    return running.load();
    */

    {
        std::unique_lock<std::mutex> lock(init_mutex_);
        // Wait until initialization_finished_ is true, with a timeout
        if (init_cv_.wait_for(lock, std::chrono::seconds(5), [this] { return initialization_finished_; })) {
            // Initialization finished within the timeout
            return running.load(); // Check the final status set by run_loop
        }
        else {
            // Timeout occurred (very bad, likely frozen)
            std::cerr << "Analyzer initialization timed out." << std::endl;
            // Attempt to clean up
            if (pcapHandle) pcap_breakloop(pcapHandle);
            if (captureThread.joinable()) captureThread.join();
            return false;
        }
    }
}

void Analyzer::stop_sniffing() {
    if (!running.load()) return;

    running = false;
    // Break the pcap_loop execution
    if (pcapHandle) {
        pcap_breakloop(pcapHandle);
    }

    if (captureThread.joinable()) {
        captureThread.join();
    }
}

// Build a snapshot for the web dashboard and reset the aggregator counters
nlohmann::json Analyzer::build_and_reset_snapshot_json(int windowSeconds) {
    nlohmann::json result;
    std::vector<std::pair<std::string, uint64_t>> talkers;
    std::map<std::string, uint64_t> protoBytes;
    uint64_t totalBytes;

    // 1. Thread-safe swap and reset
    {
        std::lock_guard<std::mutex> lock_guard(aggregator_.mutex);

        // Copy IP bytes to vector for sorting
        for (const auto& kv : aggregator_.bytesByIp) talkers.emplace_back(kv.first, kv.second);

        // Copy protocol bytes
        protoBytes = aggregator_.bytesByProtocol;
        totalBytes = aggregator_.totalBytesSinceReset;

        // Reset all counters for the next window
        aggregator_.bytesByIp.clear();
        aggregator_.bytesByProtocol.clear();
        aggregator_.totalBytesSinceReset = 0;
    }

    // 2. Process data outside the lock
    // Sort top talkers and take the top 5
    std::sort(talkers.begin(), talkers.end(), [](auto& a, auto& b) { return a.second > b.second; });
    if (talkers.size() > 5) talkers.resize(5);

    // Calculate bytes per second
    using namespace std::chrono;
    auto nowSec = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
    uint64_t bytesPerSec = windowSeconds > 0 ? static_cast<uint64_t>(totalBytes / windowSeconds) : totalBytes;

    // 3. Build JSON
    result["timestamp"] = nowSec;
    result["total_bytes_per_sec"] = bytesPerSec;

    // Top Talkers Array
    nlohmann::json talkersArr = nlohmann::json::array();
    for (auto& kv : talkers) {
        talkersArr.push_back({ {"ip", kv.first}, {"bytes", kv.second} });
    }
    result["top_talkers"] = talkersArr;

    // Protocol Breakdown Array
    nlohmann::json protoArr = nlohmann::json::array();
    uint64_t totalProtoBytes = 0;
    for (auto& kv : protoBytes) {
        totalProtoBytes += kv.second;
    }

    // Calculate percentage breakdown
    if (totalProtoBytes > 0) {
        for (auto& kv : protoBytes) {
            double percent = (static_cast<double>(kv.second) / totalProtoBytes) * 100.0;
            protoArr.push_back({ {"protocol", kv.first}, {"percent", std::round(percent)} });
        }
    }
    result["protocol_breakdown"] = protoArr;

    return result;
}


