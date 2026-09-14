#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <sstream>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <map>
#include <chrono>
#include <iomanip>
#include <algorithm>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h>
  #pragma comment(lib, "ws2_32.lib")
  #pragma comment(lib, "iphlpapi.lib")
#else
  #include <sys/socket.h  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <ifaddrs.h>
  #include <net/if.h>
  #include <unistd.h>
#endif

struct HostResult {
    std::string ip;
    bool alive = false;
    std::string mac;
    std::string vendor_hint;
};

static std::string run_command(const std::string& cmd) {
    std::array<char, 256> buffer{};
    std::string result;
#ifdef _WIN32
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd.c_str(), "r"), _pclose);
#else
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
#endif
    if (!pipe) return result;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

static bool ping_host(const std::string& ip) {
#ifdef _WIN32
    std::string cmd = "ping -n 1 -w 300 " + ip + " > nul 2>&1";
#else

    std::string cmd = "ping -c 1 -W 1 " + ip + " > /dev/null 2>&1";
#endif
    int ret = std::system(cmd.c_str());
    return ret == 0;
}

static std::map<std::string, std::string> read_arp_table() {
    std::map<std::string, std::string> table;
    std::string output;

#ifdef _WIN32
    output = run_command("arp -a");
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        std::istringstream ls(line);
        std::string ip, mac, type;
        ls >> ip >> mac >> type;
        if (ip.find('.') != std::string::npos && mac.find('-') != std::string::npos) {
            table[ip] = mac;
        }
    }
#else

    output = run_command("ip neigh show 2>/dev/null");
    if (output.empty()) {
        output = run_command("arp -an 2>/dev/null");
    }

    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {

        std::string ip, mac;

        size_t lladdr_pos = line.find("lladdr");
        if (lladdr_pos != std::string::npos) {
            std::istringstream ls(line);
            std::string token;
            ls >> ip;
            while (ls >> token) {
                if (token == "lladdr") {
                    ls >> mac;
                    break;
                }
            }
        } else {
            size_t open_paren = line.find('(');
            size_t close_paren = line.find(')');
            size_t at_pos = line.find(" at ");
            if (open_paren != std::string::npos && close_paren != std::string::npos && at_pos != std::string::npos) {
                ip = line.substr(open_paren + 1, close_paren - open_paren - 1);
                size_t mac_start = at_pos + 4;
                size_t mac_end = line.find(' ', mac_start);
                mac = line.substr(mac_start, mac_end - mac_start);
            }
        }

        if (!ip.empty() && !mac.empty() && mac != "<incomplete>") {
            table[ip] = mac;
        }
    }
#endif

    return table;
}

static std::string detect_local_subnet_prefix() {
#ifdef _WIN32

    std::string out = run_command("ipconfig");
    size_t pos = out.find("IPv4 Address");
    if (pos != std::string::npos) {
        size_t colon = out.find(':', pos);
        size_t end = out.find('\n', colon);
        std::string ip = out.substr(colon + 2, end - colon - 2);

        ip.erase(std::remove_if(ip.begin(), ip.end(), [](char c){ return c == '\r' || c == '\n' || c == ' '; }), ip.end());
        size_t last_dot = ip.find_last_of('.');
        if (last_dot != std::string::npos) return ip.substr(0, last_dot);
    }
    return "";
#else
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) return "";

    std::string prefix;
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
        inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);

        std::string ip_str(ip);
        size_t last_dot = ip_str.find_last_of('.');
        if (last_dot != std::string::npos) {
            prefix = ip_str.substr(0, last_dot);
            break;
        }
    }

    freeifaddrs(ifaddr);
    return prefix;
#endif
}

int main(int argc, char* argv[]) {
    std::string subnet_prefix;

    if (argc > 1) {
        std::string arg = argv[1];

        size_t slash = arg.find('/');
        std::string base = (slash != std::string::npos) ? arg.substr(0, slash) : arg;
        size_t last_dot = base.find_last_of('.');
        if (last_dot != std::string::npos) {
            subnet_prefix = base.substr(0, last_dot);
        }
    }

    if (subnet_prefix.empty()) {
        subnet_prefix = detect_local_subnet_prefix();
        if (subnet_prefix.empty()) {
            std::cerr << "Could not auto-detect local subnet. "
                         "Pass one explicitly, e.g.: ./network_scanner 192.168.1.0/24\n";
            return 1;
        }
        std::cout << "Auto-detected local subnet: " << subnet_prefix << ".0/24\n";
    }

    std::cout << "Scanning " << subnet_prefix << ".1 - " << subnet_prefix << ".254 ...\n";
    std::cout << "(This only pings hosts on your own local network.)\n\n";

    std::vector<HostResult> results(255);
    for (int i = 0; i < 255; ++i) {
        results[i].ip = subnet_prefix + "." + std::to_string(i + 1);
    }

    std::atomic<int> next_index{0};
    std::mutex cout_mutex;
    unsigned int hw_threads = std::thread::hardware_concurrency();
    unsigned int num_threads = std::max(4u, std::min(64u, hw_threads * 8));

    auto worker = [&]() {
        int idx;
        while ((idx = next_index.fetch_add(1)) < static_cast<int>(results.size())) {
            results[idx].alive = ping_host(results[idx].ip);
        }
    };

    std::vector<std::thread> pool;
    for (unsigned int t = 0; t < num_threads; ++t) {
        pool.emplace_back(worker);
    }
    for (auto& t : pool) t.join();


    auto arp_table = read_arp_table();
    int alive_count = 0;
    for (auto& host : results) {
        if (host.alive) {
            ++alive_count;
            auto it = arp_table.find(host.ip);
            if (it != arp_table.end()) {
                host.mac = it->second;
                if (host.mac.size() >= 8) {
                    host.vendor_hint = host.mac.substr(0, 8);
                }
            } else {
                host.mac = "(unknown - not in ARP cache)";
            }
        }
    }

    std::cout << std::left << std::setw(18) << "IP ADDRESS"
              << std::setw(20) << "MAC ADDRESS"
              << "STATUS\n";
    std::cout << std::string(55, '-') << "\n";

    for (const auto& host : results) {
        if (host.alive) {
            std::cout << std::left << std::setw(18) << host.ip
                      << std::setw(20) << host.mac
                      << "UP\n";
        }
    }

    std::cout << "\n" << alive_count << " device(s) found on the network.\n";

    return 0;
}
