// ============================================================================
// BTC PUZZLE HUNTER v4.0 - MAP SCHEDULER EDITION (PATCHED)
// Phases 1-12 Implementation
// ============================================================================

#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <chrono>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <array>
#include <utility>
#include <cstdint>
#include <climits>
#include <atomic>
#include <mutex>
#include <thread>
#include <memory>
#include <csignal>
#include <cstdlib>
#include <regex>
#include <condition_variable>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <unistd.h>
#include <sys/resource.h>

// OpenSSL includes
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>

// SECP256K1 headers (Jean Luc Pons - batch inversion)
#include "SECP256K1.h"
#include "Point.h"
#include "Int.h"
#include "IntGroup.h"

// NEW: Scheduler and unified hash
#include "MapScheduler.h"
#include "MapRange.h"
#include "Hash160.h"
#include "FastRandom.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

static constexpr int POINTS_BATCH_SIZE = 1024;   // CHANGED: was 256
static constexpr int HASH_BATCH_SIZE = 8;
static constexpr int SAVE_INTERVAL_SEC = 60;
static constexpr int DEFAULT_STAT_INTERVAL_MS = 30000;
static constexpr size_t BLOOM_FILTER_BITS = 1 << 24;
static constexpr int BLOOM_HASHES = 12;
static constexpr int MAX_THREADS = 256;
static constexpr int DEFAULT_MAX_TEMP = 85;
static constexpr int THERMAL_PAUSE_MINUTES = 15;

// ============================================================================
// SIGNAL HANDLING
// ============================================================================

static std::atomic<bool> g_shutdownRequested{false};

static void signalHandler(int sig) {
    std::cerr << "\n[SIGNAL] Caught signal " << sig << ", shutting down gracefully...\n";
    g_shutdownRequested.store(true);
}

// ============================================================================
// CLI ARGUMENT PARSER
// ============================================================================

struct CliArgs {
    std::string startRange;
    std::string endRange;
    std::vector<std::string> targetHash160s;
    int maxTemp = DEFAULT_MAX_TEMP;
    int statIntervalMs = DEFAULT_STAT_INTERVAL_MS;
    bool help = false;
    bool valid = true;
    std::string errorMsg;
    bool randomMode = false;
};

static void printUsage(const char* progName) {
    std::cout << "Usage: " << progName << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  -r START:END     Search range in hex (e.g., -r 20000000000000000:3ffffffffffffffff)\n"
              << "  -h160 HASH       Target Hash160 (40 hex chars). Repeatable.\n"
              << "  -maxtemp TEMP    Max CPU temp in Celsius (default: " << DEFAULT_MAX_TEMP << ")\n"
              << "  -stat MS         Status refresh interval ms (default: " << DEFAULT_STAT_INTERVAL_MS << ")\n"
              << "  -random          Random map mode (default: sequential)\n"
              << "  -h, --help       Show this help\n\n"
              << "Examples:\n"
              << "  " << progName << " -r 20000000000000000:3ffffffffffffffff -h160 739437bb8dd3b9e8c6f0e2f3b8a1c5d7e9f2b4a6\n"
              << "  " << progName << " -r 400000000000000000:7fffffffffffffffff -h160 f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8 -maxtemp 55\n";
}

static CliArgs parseArgs(int argc, char* argv[]) {
    CliArgs args;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") { args.help = true; return args; }
        else if (arg == "-r" && i + 1 < argc) {
            std::string range = argv[++i];
            size_t colonPos = range.find(':');
            if (colonPos == std::string::npos) {
                args.valid = false; args.errorMsg = "Invalid range format. Use START:END"; return args;
            }
            args.startRange = range.substr(0, colonPos);
            args.endRange = range.substr(colonPos + 1);
        }
        else if (arg == "-h160" && i + 1 < argc) {
            std::string hash = argv[++i];
            hash.erase(std::remove_if(hash.begin(), hash.end(), ::isspace), hash.end());
            if (hash.length() != 40) {
                args.valid = false; args.errorMsg = "Hash160 must be 40 hex chars: " + hash; return args;
            }
            for (char c : hash) { if (!std::isxdigit(c)) {
                args.valid = false; args.errorMsg = "Non-hex in Hash160: " + hash; return args;
            }}
            args.targetHash160s.push_back(hash);
        }
        else if (arg == "-maxtemp" && i + 1 < argc) {
            try { args.maxTemp = std::stoi(argv[++i]);
                if (args.maxTemp < 30 || args.maxTemp > 120) {
                    args.valid = false; args.errorMsg = "Temp must be 30-120"; return args;
                }
            } catch (...) { args.valid = false; args.errorMsg = "Invalid maxtemp"; return args; }
        }
        else if (arg == "-stat" && i + 1 < argc) {
            try { args.statIntervalMs = std::stoi(argv[++i]);
                if (args.statIntervalMs < 100 || args.statIntervalMs > 300000) {
                    args.valid = false; args.errorMsg = "Stat interval 100-300000 ms"; return args;
                }
            } catch (...) { args.valid = false; args.errorMsg = "Invalid stat interval"; return args; }
        }
        else if (arg == "-random") {
            args.randomMode = true;
        }
        else { args.valid = false; args.errorMsg = "Unknown option: " + arg; return args; }
    }
    if (!args.help) {
        if (args.startRange.empty() || args.endRange.empty()) {
            args.valid = false; args.errorMsg = "Range required. Use -r START:END"; return args;
        }
        if (args.targetHash160s.empty()) {
            args.valid = false; args.errorMsg = "At least one -h160 required"; return args;
        }
    }
    return args;
}

// ============================================================================
// THREAD AFFINITY
// ============================================================================

static void setThreadAffinity(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    #ifdef __ANDROID__
    pid_t tid = gettid();
    int rc = sched_setaffinity(tid, sizeof(cpu_set_t), &cpuset);
    #else
    pthread_t current_thread = pthread_self();
    int rc = pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
    #endif
    if (rc != 0) {
        // Silently ignore
    }
}

// ============================================================================
// CPU TEMPERATURE MONITORING
// ============================================================================

class ThermalMonitor {
private:
    int maxTemp;
    std::atomic<bool> paused{false};
    std::thread monitorThread;
    std::atomic<bool> running{false};
    std::mutex cv_mutex;
    std::condition_variable cv;

    int readTempFromZone(const std::string& path) {
        std::ifstream fs(path);
        if (!fs) return -1;
        int tempMilli;
        fs >> tempMilli;
        return tempMilli / 1000;
    }

    int getCPUTemperature() {
        const char* thermalPaths[] = {
            "/sys/class/thermal/thermal_zone0/temp",
            "/sys/class/thermal/thermal_zone1/temp",
            "/sys/class/thermal/thermal_zone2/temp",
            "/sys/class/thermal/thermal_zone3/temp",
            "/sys/class/thermal/thermal_zone4/temp",
            "/sys/class/thermal/thermal_zone5/temp",
            "/sys/class/thermal/thermal_zone6/temp",
            "/sys/class/thermal/thermal_zone7/temp",
            "/sys/class/hwmon/hwmon0/temp1_input",
            "/sys/class/hwmon/hwmon1/temp1_input",
            nullptr
        };
        int maxTempFound = -1;
        for (int i = 0; thermalPaths[i] != nullptr; i++) {
            int temp = readTempFromZone(thermalPaths[i]);
            if (temp > maxTempFound) maxTempFound = temp;
        }
        return maxTempFound;
    }

public:
    ThermalMonitor(int maxTempC) : maxTemp(maxTempC) {}
    ~ThermalMonitor() { stop(); }

    void waitForResume() {
        std::unique_lock<std::mutex> lock(cv_mutex);
        cv.wait(lock, [this]() { return !paused.load() || !running.load(); });
    }

    void start() {
        if (running.load()) return;
        running.store(true);
        paused.store(false);
        monitorThread = std::thread([this]() {
            while (running.load()) {
                int currentTemp = getCPUTemperature();
                if (currentTemp >= 0) {
                    if (currentTemp >= maxTemp && !paused.load()) {
                        paused.store(true);
                        cv.notify_all();
                        std::cout << "\n[THERMAL] CPU temp " << currentTemp
                                  << "C (max " << maxTemp << "C). Pausing "
                                  << THERMAL_PAUSE_MINUTES << " min...\n";
                        auto pauseStart = std::chrono::steady_clock::now();
                        while (paused.load() && running.load()) {
                            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::steady_clock::now() - pauseStart).count();
                            if (elapsed >= THERMAL_PAUSE_MINUTES * 60) {
                                paused.store(false);
                                cv.notify_all();
                                std::cout << "[THERMAL] Resume.\n";
                                break;
                            }
                            std::this_thread::sleep_for(std::chrono::seconds(5));
                            int newTemp = getCPUTemperature();
                            if (newTemp >= 0 && newTemp < maxTemp - 5) {
                                paused.store(false);
                                cv.notify_all();
                                std::cout << "[THERMAL] Temp dropped to " << newTemp
                                          << "C. Resuming early...\n";
                                break;
                            }
                        }
                    }
                }
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
        });
    }

    void stop() {
        running.store(false);
        paused.store(false);
        cv.notify_all();
        if (monitorThread.joinable()) monitorThread.join();
    }

    bool isPaused() const { return paused.load(); }
    int getMaxTemp() const { return maxTemp; }
};

// ============================================================================
// LOCK-FREE BLOOM FILTER
// ============================================================================

class alignas(64) BloomFilter {
private:
    std::vector<std::atomic<uint8_t>> filter;
    std::atomic<size_t> count{0};
    inline uint64_t hash_mix(uint64_t h) const {
        h ^= h >> 33; h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33; h *= 0xc4ceb9fe1a85ec53ULL;
        h ^= h >> 33; return h;
    }
    inline void hash_bytes(const uint8_t* data, size_t len, uint64_t& h1, uint64_t& h2) const {
        h1 = 0xcbf29ce484222325ULL; h2 = 0x84222325cbf29ce4ULL;
        for (size_t i = 0; i < len; i++) {
            h1 ^= data[i]; h1 *= 0x100000001b3ULL;
            h2 ^= data[i] + 0x9e3779b9; h2 = (h2 << 13) | (h2 >> 51); h2 *= 0x100000001b3ULL;
        }
        h1 = hash_mix(h1); h2 = hash_mix(h2);
    }
public:
    BloomFilter() : filter((BLOOM_FILTER_BITS + 7) / 8) {
        for(auto& f : filter) f.store(0, std::memory_order_relaxed);
    }
    void add(const uint8_t* data, size_t len) {
        uint64_t h1, h2; hash_bytes(data, len, h1, h2);
        for (int i = 0; i < BLOOM_HASHES; i++) {
            uint64_t h = (h1 + i * h2) % BLOOM_FILTER_BITS;
            filter[h / 8].fetch_or(1 << (h % 8), std::memory_order_release);
        }
        count.fetch_add(1, std::memory_order_relaxed);
    }
    bool test(const uint8_t* data, size_t len) const {
        uint64_t h1, h2; hash_bytes(data, len, h1, h2);
        for (int i = 0; i < BLOOM_HASHES; i++) {
            uint64_t h = (h1 + i * h2) % BLOOM_FILTER_BITS;
            if (!(filter[h / 8].load(std::memory_order_acquire) & (1 << (h % 8)))) return false;
        }
        return true;
    }
    size_t getCount() const { return count.load(); }
};

// ============================================================================
// PERFORMANCE COUNTERS
// ============================================================================

struct alignas(64) ThreadStats {
    std::atomic<unsigned long long> checked{0};
    std::atomic<unsigned long long> candidates{0};
    char padding[64 - 2 * sizeof(std::atomic<unsigned long long>)];
};

// ============================================================================
// GLOBAL STATE
// ============================================================================

static std::atomic<bool> g_matchFound{false};
static std::atomic<unsigned long long> g_matchesFound{0};
static std::atomic<unsigned long long> g_totalChecked{0};
static std::atomic<unsigned long long> g_totalCandidates{0};
static std::atomic<bool> g_thermalPaused{false};

static std::string g_foundPrivKey;
static std::string g_foundPubKey;
static std::mutex g_foundMutex;

// ============================================================================
// HELPERS
// ============================================================================

static inline std::string bytesToHex(const uint8_t* data, size_t len) {
    static constexpr char lut[] = "0123456789abcdef";
    std::string out; out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = data[i];
        out.push_back(lut[b >> 4]); out.push_back(lut[b & 0x0F]);
    }
    return out;
}

static inline std::string padHexTo64(const std::string& h) {
    return (h.size() >= 64) ? h : std::string(64 - h.size(), '0') + h;
}

static inline Int hexToInt(const std::string& h) {
    Int n; char buf[65] = {0}; std::strncpy(buf, h.c_str(), 64); n.SetBase16(buf); return n;
}

static inline std::string intToHex(const Int& v) {
    Int t; t.Set((Int*)&v); return t.GetBase16();
}

static inline std::string intXToHex64(const Int& x) {
    Int t; t.Set((Int*)&x); std::string h = t.GetBase16();
    if (h.size() < 64) h.insert(0, 64 - h.size(), '0'); return h;
}

static inline bool isEven(const Int& n) { return n.IsEven(); }

static inline std::string pointToCompressedHex(const Point& p) {
    return (isEven(p.y) ? "02" : "03") + intXToHex64(p.x);
}

static inline void pointToCompressedBin(const Point& p, uint8_t out[33]) {
    out[0] = isEven(p.y) ? 0x02 : 0x03;
    Int t; t.Set((Int*)&p.x);
    for (int i = 0; i < 32; ++i) out[1 + i] = uint8_t(t.GetByte(31 - i));
}

static void writeFoundKey(const std::string& privHex, const std::string& hash160Hex) {
    std::ofstream ofs("found.txt", std::ios::app);
    if (!ofs) { std::cerr << "Cannot open found.txt\n"; return; }
    ofs << "Hash160: " << hash160Hex << "\nPrivate Key: " << privHex << "\n\n"; ofs.flush();
}

static void appendCandidateToFile(const std::string& privHex, const std::string& hash160Hex) {
    static std::mutex candidatesMutex;
    std::lock_guard<std::mutex> lock(candidatesMutex);
    std::ofstream ofs("candidates.txt", std::ios::app);
    if (ofs) { ofs << "Private Key: " << privHex << "\nHash160: " << hash160Hex << "\n\n"; ofs.flush(); }
}

static std::string formatElapsedTime(double sec) {
    int h = int(sec) / 3600, m = (int(sec) % 3600) / 60, s = int(sec) % 60;
    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << h << ":" << std::setw(2) << m << ":" << std::setw(2) << s;
    return oss.str();
}

static std::string formatLargeNumber(unsigned long long num) {
    std::string str = std::to_string(num), result; int count = 0;
    for (int i = str.length() - 1; i >= 0; i--) {
        if (count == 3) { result = "," + result; count = 0; }
        result = str[i] + result; count++;
    }
    return result;
}

static std::string getMemoryUsage() {
    long page_size = sysconf(_SC_PAGESIZE);
    long num_pages = sysconf(_SC_PHYS_PAGES);
    long available_pages = sysconf(_SC_AVPHYS_PAGES);
    long used_mb = (num_pages - available_pages) * page_size / (1024 * 1024);
    long total_mb = num_pages * page_size / (1024 * 1024);
    std::ostringstream oss;
    oss << used_mb << "/" << total_mb << " MB";
    return oss.str();
}

static inline bool strEqualsIgnoreCase(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
    }
    return true;
}

// ============================================================================
// MAIN HUNTER CLASS - COOPERATIVE MAP SCHEDULER
// ============================================================================

class PuzzleHunter {
public:
    std::vector<std::vector<uint8_t>> targetHash160s;
private:
    Secp256K1 secp;
    Int startRange, endRange;
    std::unique_ptr<BloomFilter> bloom;
    std::unique_ptr<CooperativeMapScheduler> scheduler;
    int numThreads;
    int statIntervalMs;
    ThermalMonitor* thermalMonitor;
    ScanMode scanMode;
    std::string progressFile;
    std::atomic<bool> saveRequested{false};
    std::mutex progressMutex;

public:
    PuzzleHunter(int statMs = DEFAULT_STAT_INTERVAL_MS, ThermalMonitor* therm = nullptr,
                 ScanMode mode = ScanMode::SEQUENTIAL)
        : statIntervalMs(statMs), thermalMonitor(therm), scanMode(mode),
          progressFile("Progress.dat") {
        secp.Init();
        numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4;
        scheduler = std::make_unique<CooperativeMapScheduler>();
        scheduler->setMode(mode);
    }

    void addTarget(const std::string& hash160Hex) {
        std::vector<uint8_t> hash(20);
        for (int i = 0; i < 20; i++) sscanf(hash160Hex.c_str() + 2 * i, "%02hhx", &hash[i]);
        targetHash160s.push_back(hash);
    }

    void setRange(const std::string& startHex, const std::string& endHex) {
        startRange = hexToInt(startHex);
        endRange = hexToInt(endHex);
    }

    void setScanMode(ScanMode mode) {
        scanMode = mode;
        scheduler->setMode(mode);
    }

    void initBloom() {
        if (!bloom) {
            bloom = std::make_unique<BloomFilter>();
            for (const auto& target : targetHash160s) bloom->add(target.data(), 20);
        }
    }

    void initialize() {
        initBloom();
        scheduler->initialize(startRange, endRange);

        std::cout << "[SCHEDULER] Total maps: " << scheduler->getTotalMaps() << "\n";
        std::cout << "[SCHEDULER] Map size:   ~" << formatLargeNumber(scheduler->getMapSize()) << " keys\n";
        std::cout << "[SCHEDULER] Mode:       " << (scanMode == ScanMode::SEQUENTIAL ? "Sequential" : "Random") << "\n";
    }

    bool checkResume(const std::string& startHex, const std::string& endHex,
                     const std::vector<std::string>& targetHashes) {
        std::ifstream test("Progress.dat");
        if (!test.good()) return false;

        std::cout << "\n[RESUME] Found Progress.dat. Validate? (y/n): ";
        std::string response;
        std::getline(std::cin, response);

        if (response != "y" && response != "Y") return false;

        ScanMode loadedMode;
        uint64_t loadedCurrentMap = 0;
        Int loadedOffset;
        std::string loadedStart, loadedEnd;
        std::vector<std::string> loadedTargets;

        if (!scheduler->loadProgress(progressFile, loadedMode, loadedCurrentMap, loadedOffset,
                                     loadedStart, loadedEnd, loadedTargets)) {
            std::cout << "[RESUME] Failed to load progress file.\n";
            return false;
        }

        if (!strEqualsIgnoreCase(loadedStart, startHex) || !strEqualsIgnoreCase(loadedEnd, endHex)) {
            std::cout << "[RESUME] Range mismatch! Saved: " << loadedStart << "-" << loadedEnd
                      << " Current: " << startHex << "-" << endHex << "\n";
            return false;
        }

        if (loadedTargets.size() != targetHashes.size()) {
            std::cout << "[RESUME] Target count mismatch.\n";
            return false;
        }
        for (size_t i = 0; i < loadedTargets.size(); i++) {
            if (!strEqualsIgnoreCase(loadedTargets[i], targetHashes[i])) {
                std::cout << "[RESUME] Target hash mismatch at index " << i << "\n";
                return false;
            }
        }

        scanMode = loadedMode;
        scheduler->setMode(loadedMode);

        std::cout << "[RESUME] Restored: Map " << loadedCurrentMap
                  << ", Offset " << intToHex(loadedOffset) << "\n";
        std::cout << "[RESUME] Completed: " << scheduler->getCompletedMaps() << " / "
                  << scheduler->getTotalMaps() << " maps\n";

        initBloom();
        return true;
    }

    void workerThread(int tid, ThreadStats& stats) {
        setThreadAffinity(tid);

        std::vector<Int> batchPrivKeys(POINTS_BATCH_SIZE);
        std::vector<Point> ptBatch(POINTS_BATCH_SIZE);
        Hash160 hasher;
        uint8_t pubKeys[HASH_BATCH_SIZE][33];
        uint8_t hashRes[HASH_BATCH_SIZE][20];
        unsigned long long localChecked = 0, localCandidates = 0;

        while (!g_matchFound.load(std::memory_order_relaxed) && !g_shutdownRequested.load()) {
            if (thermalMonitor && thermalMonitor->isPaused()) {
                g_thermalPaused.store(true);
                thermalMonitor->waitForResume();
                continue;
            }
            g_thermalPaused.store(false);

            int batchCount = scheduler->getNextBatch(batchPrivKeys.data(), POINTS_BATCH_SIZE);

            if (batchCount == 0) {
                if (scheduler->isComplete()) break;
                std::this_thread::yield();
                continue;
            }

            secp.ComputePublicKeyBatch(batchPrivKeys.data(), batchCount, ptBatch.data());

            for (int batchStart = 0; batchStart < batchCount; batchStart += HASH_BATCH_SIZE) {
                int batchEnd = std::min(batchStart + HASH_BATCH_SIZE, batchCount);
                int thisBatchSize = batchEnd - batchStart;

                for (int i = 0; i < thisBatchSize; ++i) {
                    pointToCompressedBin(ptBatch[batchStart + i], pubKeys[i]);
                }
                hasher.computeBatch(pubKeys, hashRes, thisBatchSize);

                for (int i = 0; i < thisBatchSize; ++i) {
                    ++localChecked;
                    if (!bloom->test(hashRes[i], 20)) continue;

                    std::string hash160Hex = bytesToHex(hashRes[i], 20);
                    Int& actualPrivKey = batchPrivKeys[batchStart + i];
                    std::string privHex = padHexTo64(intToHex(actualPrivKey));
                    appendCandidateToFile(privHex, hash160Hex);
                    ++localCandidates;

                    for (const auto& target : targetHash160s) {
                        if (std::memcmp(hashRes[i], target.data(), 20) == 0) {
                            bool expected = false;
                            if (g_matchFound.compare_exchange_strong(expected, true)) {
                                std::lock_guard<std::mutex> lock(g_foundMutex);
                                g_foundPrivKey = privHex;
                                g_foundPubKey = pointToCompressedHex(ptBatch[batchStart + i]);
                                g_matchesFound++;
                                writeFoundKey(g_foundPrivKey, hash160Hex);
                            }
                            return;
                        }
                    }
                }
            }

            if (localChecked % 10000 == 0) {
                stats.checked.fetch_add(localChecked, std::memory_order_relaxed);
                stats.candidates.fetch_add(localCandidates, std::memory_order_relaxed);
                g_totalChecked.fetch_add(localChecked, std::memory_order_relaxed);
                g_totalCandidates.fetch_add(localCandidates, std::memory_order_relaxed);
                localChecked = 0; localCandidates = 0;
            }
        }

        stats.checked.fetch_add(localChecked, std::memory_order_relaxed);
        stats.candidates.fetch_add(localCandidates, std::memory_order_relaxed);
        g_totalChecked.fetch_add(localChecked, std::memory_order_relaxed);
        g_totalCandidates.fetch_add(localCandidates, std::memory_order_relaxed);
    }

    void run() {
        auto tStart = std::chrono::high_resolution_clock::now();

        std::vector<ThreadStats> threadStats(numThreads);
        std::vector<std::thread> threads;

        for (int tid = 0; tid < numThreads; ++tid) {
            threads.emplace_back([this, tid, &threadStats]() {
                this->workerThread(tid, threadStats[tid]);
            });
        }

        std::thread statThread([this, tStart, &threadStats]() {
            auto lastSave = std::chrono::steady_clock::now();

            while (!g_matchFound.load(std::memory_order_relaxed) && !g_shutdownRequested.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(statIntervalMs));

                auto now = std::chrono::high_resolution_clock::now();
                double elapsed = std::chrono::duration<double>(now - tStart).count();
                unsigned long long total = g_totalChecked.load();
                double kps = (elapsed > 0) ? total / elapsed : 0;

                uint64_t completed = scheduler->getCompletedMaps();
                uint64_t totalMaps = scheduler->getTotalMaps();
                uint64_t remaining = totalMaps - completed;
                double percent = scheduler->getOverallPercent();

                double mapsPerSec = (elapsed > 0) ? (double)completed / elapsed : 0;
                double estRemainingSec = (mapsPerSec > 0) ? remaining / mapsPerSec : 0;

                std::string thermalStatus = g_thermalPaused.load() ? " [THERMAL PAUSE]" : "";
                std::string memUsage = getMemoryUsage();

                auto nowSteady = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(nowSteady - lastSave).count() >= SAVE_INTERVAL_SEC) {
                    Int saveOffset = scheduler->getCurrentOffset();

                    std::vector<std::string> targetStrs;
                    for (const auto& t : targetHash160s) {
                        targetStrs.push_back(bytesToHex(t.data(), 20));
                    }

                    scheduler->saveProgress(progressFile, scanMode, saveOffset,
                                           intToHex(startRange), intToHex(endRange), targetStrs);
                    lastSave = nowSteady;
                }

                std::cout << "\033[2J\033[H";

                std::string estStr = (mapsPerSec > 0.0 && remaining > 0)
                                     ? formatElapsedTime(estRemainingSec)
                                     : "N/A";

                std::cout << "╔══════════════════════════════════════════════════════════════╗\n"
                          << "║         BTC PUZZLE HUNTER v4.0 - COOPERATIVE MAPS            ║\n"
                          << "╠══════════════════════════════════════════════════════════════╣\n"
                          << "║ Threads:    " << std::setw(3) << numThreads
                          << " / " << std::setw(3) << std::thread::hardware_concurrency() << " active          ║\n"
                          << "║ Mode:       " << std::setw(10) << (scanMode == ScanMode::SEQUENTIAL ? "Sequential" : "Random    ") << "              ║\n"
                          << "╠══════════════════════════════════════════════════════════════╣\n"
                          << "║ MAP PROGRESS                                                 ║\n"
                          << "║ Maps:       " << std::setw(8) << completed << " / " << std::setw(8) << totalMaps << "          ║\n"
                          << "║ Remaining:  " << std::setw(8) << remaining << "                        ║\n"
                          << "║ Progress:   " << std::setw(10) << std::fixed << std::setprecision(2) << percent << "%                  ║\n"
                          << "║ Current Map: " << std::setw(8) << scheduler->getCurrentMapId() << "                        ║\n"
                          << "╠══════════════════════════════════════════════════════════════╣\n"
                          << "║ KEY PROGRESS                                                 ║\n"
                          << "║ Keys/sec:   " << std::setw(12) << std::fixed << std::setprecision(0) << kps << "              ║\n"
                          << "║ Total:      " << std::setw(18) << formatLargeNumber(total) << "        ║\n"
                          << "║ Elapsed:    " << std::setw(10) << formatElapsedTime(elapsed) << "                  ║\n"
                          << "║ Candidates:  " << std::setw(8) << g_totalCandidates.load() << "                        ║\n"
                          << "║ Matches:     " << std::setw(8) << g_matchesFound.load() << "                        ║\n"
                          << "╠══════════════════════════════════════════════════════════════╣\n"
                          << "║ SYSTEM                                                       ║\n"
                          << "║ Memory:      " << std::setw(15) << memUsage << "             ║\n"
                          << "║ Est. Remain: " << std::setw(10) << estStr << "                  ║\n"
                          << "║ Refresh:     " << std::setw(6) << statIntervalMs << " ms" << std::setw(18) << ""
                          << thermalStatus << std::setw(20 - thermalStatus.length()) << "║\n"
                          << "╚══════════════════════════════════════════════════════════════╝\n";
            }
        });

        for (auto& t : threads) t.join();
        g_matchFound.store(true);
        statThread.join();

        auto tEnd = std::chrono::high_resolution_clock::now();
        double totalElapsed = std::chrono::duration<double>(tEnd - tStart).count();

        std::vector<std::string> targetStrs;
        for (const auto& t : targetHash160s) targetStrs.push_back(bytesToHex(t.data(), 20));
        Int finalOffset;
        finalOffset.Set(&endRange);
        scheduler->saveProgress(progressFile, scanMode, finalOffset,
                               intToHex(startRange), intToHex(endRange), targetStrs);

        std::cout << "\033[2J\033[H";
        if (g_matchesFound.load() > 0) {
            std::cout << "╔══════════════════════════════════════════════════════════════╗\n"
                      << "║                    MATCH FOUND!                              ║\n"
                      << "╠══════════════════════════════════════════════════════════════╣\n"
                      << "║ Private Key: " << g_foundPrivKey << " ║\n"
                      << "║ Public Key:  " << g_foundPubKey << " ║\n"
                      << "╚══════════════════════════════════════════════════════════════╝\n";
        } else {
            std::cout << "╔══════════════════════════════════════════════════════════════╗\n"
                      << "║                 SEARCH COMPLETED                             ║\n"
                      << "╠══════════════════════════════════════════════════════════════╣\n"
                      << "║ Maps Done:    " << std::setw(8) << scheduler->getCompletedMaps()
                      << " / " << scheduler->getTotalMaps() << "              ║\n"
                      << "║ Total checked: " << std::setw(18) << formatLargeNumber(g_totalChecked.load()) << "       ║\n"
                      << "║ Time:         " << std::setw(10) << formatElapsedTime(totalElapsed) << "                  ║\n"
                      << "║ Avg k/s:      " << std::setw(12) << std::fixed << std::setprecision(0)
                      << (totalElapsed > 0 ? g_totalChecked.load() / totalElapsed : 0) << "              ║\n"
                      << "╚══════════════════════════════════════════════════════════════╝\n";
        }
    }
};

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    CliArgs args = parseArgs(argc, argv);
    if (args.help) { printUsage(argv[0]); return 0; }
    if (!args.valid) { std::cerr << "Error: " << args.errorMsg << "\n\n"; printUsage(argv[0]); return 1; }

    ScanMode mode = args.randomMode ? ScanMode::RANDOM : ScanMode::SEQUENTIAL;

    std::cout << "╔══════════════════════════════════════════════════════════════╗\n"
              << "║     BTC Puzzle Hunter v4.0 - COOPERATIVE MAPS                ║\n"
              << "║     All Threads + One Map + Batch Inversion + Resume         ║\n"
              << "╚══════════════════════════════════════════════════════════════╝\n\n";

    std::cout << "[CONFIG] Range: " << args.startRange << " to " << args.endRange << "\n";
    std::cout << "[CONFIG] Targets: " << args.targetHash160s.size() << "\n";
    std::cout << "[CONFIG] Max Temp: " << args.maxTemp << "C\n";
    std::cout << "[CONFIG] Stat Interval: " << args.statIntervalMs << " ms\n";
    std::cout << "[CONFIG] Threads: " << std::thread::hardware_concurrency() << "\n";
    std::cout << "[CONFIG] Mode: " << (mode == ScanMode::SEQUENTIAL ? "Sequential" : "Random") << "\n\n";

    OpenSSL_add_all_algorithms();

    ThermalMonitor thermalMonitor(args.maxTemp);
    thermalMonitor.start();

    PuzzleHunter hunter(args.statIntervalMs, &thermalMonitor, mode);
    for (const auto& hash : args.targetHash160s) hunter.addTarget(hash);
    hunter.setRange(args.startRange, args.endRange);
    hunter.setScanMode(mode);

    bool resumed = hunter.checkResume(args.startRange, args.endRange, args.targetHash160s);

    if (!resumed) {
        hunter.initialize();
    } else {
        std::cout << "[MAIN] Resuming from saved progress, skipping fresh initialization.\n";
    }

    std::cout << "Starting optimized search...\n";
    std::this_thread::sleep_for(std::chrono::seconds(1));

    hunter.run();
    thermalMonitor.stop();

    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}
