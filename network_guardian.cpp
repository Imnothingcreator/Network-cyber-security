#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <array>
#include <memory>
#include <algorithm>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>

static std::atomic<bool> g_running{true};

void handle_signal(int) {
    g_running = false;
}

static std::string run_command(const std::string& cmd) {
    std::array<char, 256> buffer{};
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return result;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

static std::string now_timestamp() {
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

static bool ping_host(const std::string& ip) {
    std::string cmd = "ping -c 1 -W 1 " + ip + " > /dev/null 2>&1";
    return std::system(cmd.c_str()) == 0;
}

static std::map<std::string, std::string> read_arp_table() {
    std::map<std::string, std::string> table;
    std::string output = run_command("ip neigh show 2>/dev/null");
    if (output.empty()) output = run_command("arp -an 2>/dev/null");

    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        std::string ip, mac;
        size_t lladdr_pos = line.find("lladdr");
        if (lladdr_pos != std::string::npos) {
            std::istringstream ls(line);
            ls >> ip;
            std::string token;
            while (ls >> token) {
                if (token == "lladdr") { ls >> mac; break; }
            }
        } else {
            size_t op = line.find('(');
            size_t cp = line.find(')');
            size_t at = line.find(" at ");
            if (op != std::string::npos && cp != std::string::npos && at != std::string::npos) {
                ip = line.substr(op + 1, cp - op - 1);
                size_t ms = at + 4;
                size_t me = line.find(' ', ms);
                mac = line.substr(ms, me - ms);
            }
        }
        if (!ip.empty() && !mac.empty() && mac != "<incomplete>") table[ip] = mac;
    }
    return table;
}

static std::string detect_local_subnet_prefix() {
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) return "";
    std::string prefix;
    for (auto ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        char ip[INET_ADDRSTRLEN];
        auto addr = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
        inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);
        std::string ip_str(ip);
        size_t dot = ip_str.find_last_of('.');
        if (dot != std::string::npos) { prefix = ip_str.substr(0, dot); break; }
    }
    freeifaddrs(ifaddr);
    return prefix;
}


static bool check_port(const std::string& ip, int port, int timeout_ms = 300) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    fcntl(sock, F_SETFL, O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    bool open = false;
    int res = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (res == 0) {
        open = true;
    } else if (errno == EINPROGRESS) {
        fd_set wait_set;
        FD_ZERO(&wait_set);
        FD_SET(sock, &wait_set);
        timeval timeout{};
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        if (select(sock + 1, nullptr, &wait_set, nullptr, &timeout) > 0) {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            open = (so_error == 0);
        }
    }
    close(sock);
    return open;
}

static void notify(const std::string& title, const std::string& body) {
    // Fails silently if notify-send isn't installed - everything else still works.
    std::string cmd = "notify-send \"" + title + "\" \"" + body + "\" 2>/dev/null";
    std::system(cmd.c_str());
}

struct DeviceRecord {
    std::string mac;
    std::string first_seen;
    std::string last_seen;
    bool online = false;
};

class DeviceRegistry {
public:
    explicit DeviceRegistry(std::string log_path) : log_path_(std::move(log_path)) {
        load();
    }

    bool update(const std::string& ip, const std::string& mac) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(ip);
        std::string ts = now_timestamp();
        bool is_new = (it == devices_.end());
        if (is_new) {
            devices_[ip] = {mac, ts, ts, true};
        } else {
            it->second.last_seen = ts;
            it->second.online = true;
            if (!mac.empty()) it->second.mac = mac;
        }
        return is_new;
    }

    std::vector<std::string> mark_offline_except(const std::set<std::string>& online_ips) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> newly_offline;
        for (auto& [ip, rec] : devices_) {
            if (rec.online && online_ips.find(ip) == online_ips.end()) {
                rec.online = false;
                newly_offline.push_back(ip);
            }
        }
        return newly_offline;
    }

    void save() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ofstream out(log_path_, std::ios::trunc);
        for (auto& [ip, rec] : devices_) {
            out << ip << "," << rec.mac << "," << rec.first_seen << ","
                << rec.last_seen << "," << (rec.online ? "1" : "0") << "\n";
        }
    }

    void print_summary() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "\n" << std::left << std::setw(16) << "IP"
                  << std::setw(20) << "MAC"
                  << std::setw(12) << "STATUS"
                  << std::setw(20) << "FIRST SEEN" << "LAST SEEN\n";
        std::cout << std::string(80, '-') << "\n";
        for (auto& [ip, rec] : devices_) {
            std::cout << std::left << std::setw(16) << ip
                      << std::setw(20) << rec.mac
                      << std::setw(12) << (rec.online ? "ONLINE" : "offline")
                      << std::setw(20) << rec.first_seen << rec.last_seen << "\n";
        }
    }

private:
    void load() {
        std::ifstream in(log_path_);
        if (!in) return;
        std::string line;
        while (std::getline(in, line)) {
            std::istringstream ls(line);
            std::string ip, mac, first, last, online_str;
            std::getline(ls, ip, ',');
            std::getline(ls, mac, ',');
            std::getline(ls, first, ',');
            std::getline(ls, last, ',');
            std::getline(ls, online_str, ',');
            if (!ip.empty()) {
                devices_[ip] = {mac, first, last, false};
            }
        }
    }

    std::string log_path_;
    std::map<std::string, DeviceRecord> devices_;
    std::mutex mutex_;
};

struct Config {
    std::string subnet_prefix;
    int interval_seconds = 30;
    bool once = false;
    bool port_scan = true;
};

static Config parse_args(int argc, char* argv[]) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--once") {
            cfg.once = true;
        } else if (arg == "--no-portscan") {
            cfg.port_scan = false;
        } else if (arg == "--interval" && i + 1 < argc) {
            cfg.interval_seconds = std::atoi(argv[++i]);
        } else if (arg == "--subnet" && i + 1 < argc) {
            std::string s = argv[++i];
            size_t slash = s.find('/');
            std::string base = (slash != std::string::npos) ? s.substr(0, slash) : s;
            size_t dot = base.find_last_of('.');
            if (dot != std::string::npos) cfg.subnet_prefix = base.substr(0, dot);
        }
    }
    return cfg;
}

static const std::vector<std::pair<int, std::string>> kCommonPorts = {
    {22, "SSH"}, {80, "HTTP"}, {443, "HTTPS"}, {445, "SMB"},
    {3389, "RDP"}, {8080, "HTTP-ALT"}, {5000, "UPnP/Dev"}
};

int main(int argc, char* argv[]) {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    Config cfg = parse_args(argc, argv);

    if (cfg.subnet_prefix.empty()) {
        cfg.subnet_prefix = detect_local_subnet_prefix();
        if (cfg.subnet_prefix.empty()) {
            std::cerr << "Could not auto-detect local subnet. Pass one with --subnet 192.168.1.0/24\n";
            return 1;
        }
    }

    std::string log_path = "network_guardian_devices.csv";
    DeviceRegistry registry(log_path);

    std::cout << "Network Guardian - monitoring " << cfg.subnet_prefix << ".0/24\n";
    std::cout << "Interval: " << cfg.interval_seconds << "s | Port scan: "
              << (cfg.port_scan ? "on" : "off") << " | Press Ctrl+C to stop\n\n";

    do {
        std::vector<std::string> ips(254);
        for (int i = 0; i < 254; ++i) ips[i] = cfg.subnet_prefix + "." + std::to_string(i + 1);

        std::atomic<int> next_index{0};
        std::vector<std::string> alive_ips_vec(254);
        unsigned int threads = std::max(4u, std::min(64u, std::thread::hardware_concurrency() * 8));

        auto worker = [&]() {
            int idx;
            while ((idx = next_index.fetch_add(1)) < 254) {
                if (ping_host(ips[idx])) alive_ips_vec[idx] = ips[idx];
            }
        };
        std::vector<std::thread> pool;
        for (unsigned int t = 0; t < threads; ++t) pool.emplace_back(worker);
        for (auto& t : pool) t.join();

        auto arp_table = read_arp_table();
        std::set<std::string> online_ips;

        for (auto& ip : alive_ips_vec) {
            if (ip.empty()) continue;
            online_ips.insert(ip);
            std::string mac = arp_table.count(ip) ? arp_table[ip] : "";
            bool is_new = registry.update(ip, mac);
            if (is_new) {
                std::cout << "[" << now_timestamp() << "] NEW DEVICE: " << ip
                          << (mac.empty() ? "" : " (" + mac + ")") << "\n";
                notify("New device on network", ip + (mac.empty() ? "" : " - " + mac));

                if (cfg.port_scan) {
                    for (auto& [port, name] : kCommonPorts) {
                        if (check_port(ip, port)) {
                            std::cout << "    open port " << port << " (" << name << ")\n";
                        }
                    }
                }
            }
        }

        auto newly_offline = registry.mark_offline_except(online_ips);
        for (auto& ip : newly_offline) {
            std::cout << "[" << now_timestamp() << "] device went offline: " << ip << "\n";
        }

        registry.save();

        if (!cfg.once) {
            registry.print_summary();
            std::cout << "\nNext scan in " << cfg.interval_seconds << "s...\n" << std::flush;
            for (int s = 0; s < cfg.interval_seconds && g_running; ++s) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    } while (g_running && !cfg.once);

    registry.print_summary();
    std::cout << "\nDevice history saved to " << log_path << "\n";
    return 0;
}
