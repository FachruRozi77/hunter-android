// ============================================================================
// BTC PUZZLE HUNTER v2.1 - ARM Optimized with CLI Args & Thermal Management
// For 1000 Bitcoin Puzzle Transaction
// Maximum performance on ARM64 with NEON support
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
#include <queue>
#include <condition_variable>
#include <cmath>
#include <csignal>
#include <cstdlib>
#include <regex>

// OpenSSL includes
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>

// ARM NEON support
#if defined(__aarch64__)
#include <arm_neon.h>
#define USE_NEON 1
#else
#define USE_NEON 0
#endif

// OpenMP for maximum parallelism
#ifdef _OPENMP
#include <omp.h>
#define USE_OPENMP 1
#else
#define USE_OPENMP 0
#endif

// SECP256K1 headers
#include "SECP256K1.h"
#include "Point.h"
#include "Int.h"
#include "IntGroup.h"

// ============================================================================
// CONFIGURATION - Optimized for maximum performance
// ============================================================================

// Batch sizes - tuned for ARM64 cache hierarchy
static constexpr int POINTS_BATCH_SIZE = 4096;      // Larger batch for better throughput
static constexpr int HASH_BATCH_SIZE = 64;           // Process 64 hashes at once
static constexpr int SAVE_INTERVAL_SEC = 60;        // More frequent saves

// Default status refresh interval (30 seconds = 30000 ms)
static constexpr int DEFAULT_STAT_INTERVAL_MS = 30000;

// Bloom filter - sized for multiple targets (1000 puzzle addresses)
static constexpr size_t BLOOM_FILTER_BITS = 1 << 24;  // 16MB for low false positive
static constexpr int BLOOM_HASHES = 12;

// Threading
static constexpr int MAX_THREADS = 256;              // Allow all cores including SMT

// Thermal management defaults
static constexpr int DEFAULT_MAX_TEMP = 85;          // Default max temp in Celsius
static constexpr int THERMAL_PAUSE_MINUTES = 15;     // Pause duration when overheating

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
};

static void printUsage(const char* progName) {
    std::cout << "Usage: " << progName << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  -r START:END     Search range in hex (e.g., -r 20000000000000000:3ffffffffffffffff)\n"
              << "  -h160 HASH       Target Hash160 (40 hex chars). Can be used multiple times.\n"
              << "  -maxtemp TEMP    Max CPU temperature in Celsius (default: " << DEFAULT_MAX_TEMP << ")\n"
              << "  -stat MS         Status refresh interval in milliseconds (default: " << DEFAULT_STAT_INTERVAL_MS << ")\n"
              << "  -h, --help       Show this help message\n\n"
              << "Examples:\n"
              << "  " << progName << " -r 20000000000000000:3ffffffffffffffff -h160 739437bb8dd3b9e8c6f0e2f3b8a1c5d7e9f2b4a6\n"
              << "  " << progName << " -r 40000000000000000:7ffffffffffffffff -h160 abc123... -h160 def456... -maxtemp 80\n";
}

static CliArgs parseArgs(int argc, char* argv[]) {
    CliArgs args;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            args.help = true;
            return args;
        }
        else if (arg == "-r" && i + 1 < argc) {
            std::string range = argv[++i];
            size_t colonPos = range.find(':');
            if (colonPos == std::string::npos) {
                args.valid = false;
                args.errorMsg = "Invalid range format. Use START:END (e.g., 20000000000000000:3ffffffffffffffff)";
                return args;
            }
            args.startRange = range.substr(0, colonPos);
            args.endRange = range.substr(colonPos + 1);
        }
        else if (arg == "-h160" && i + 1 < argc) {
            std::string hash = argv[++i];
            // Remove any whitespace
            hash.erase(std::remove_if(hash.begin(), hash.end(), ::isspace), hash.end());
            if (hash.length() != 40) {
                args.valid = false;
                args.errorMsg = "Hash160 must be exactly 40 hex characters: " + hash;
                return args;
            }
            // Validate hex
            for (char c : hash) {
                if (!std::isxdigit(c)) {
                    args.valid = false;
                    args.errorMsg = "Hash160 contains non-hex characters: " + hash;
                    return args;
                }
            }
            args.targetHash160s.push_back(hash);
        }
        else if (arg == "-maxtemp" && i + 1 < argc) {
            try {
                args.maxTemp = std::stoi(argv[++i]);
                if (args.maxTemp < 30 || args.maxTemp > 120) {
                    args.valid = false;
                    args.errorMsg = "Max temperature must be between 30 and 120 Celsius";
                    return args;
                }
            } catch (...) {
                args.valid = false;
                args.errorMsg = "Invalid max temperature value";
                return args;
            }
        }
        else if (arg == "-stat" && i + 1 < argc) {
            try {
                args.statIntervalMs = std::stoi(argv[++i]);
                if (args.statIntervalMs < 100 || args.statIntervalMs > 300000) {
                    args.valid = false;
                    args.errorMsg = "Stat interval must be between 100 and 300000 ms";
                    return args;
                }
            } catch (...) {
                args.valid = false;
                args.errorMsg = "Invalid stat interval value";
                return args;
            }
        }
        else {
            args.valid = false;
            args.errorMsg = "Unknown option: " + arg;
            return args;
        }
    }

    // Validate required args
    if (!args.help) {
        if (args.startRange.empty() || args.endRange.empty()) {
            args.valid = false;
            args.errorMsg = "Range required. Use -r START:END";
            return args;
        }
        if (args.targetHash160s.empty()) {
            args.valid = false;
            args.errorMsg = "At least one target Hash160 required. Use -h160 HASH";
            return args;
        }
    }

    return args;
}

// ============================================================================
// CPU TEMPERATURE MONITORING (Linux/Android)
// ============================================================================

class ThermalMonitor {
private:
    int maxTemp;
    std::atomic<bool> paused{false};
    std::thread monitorThread;
    std::atomic<bool> running{false};

    // Try to read temperature from various thermal zones
    int readTempFromZone(const std::string& path) {
        std::ifstream fs(path);
        if (!fs) return -1;
        int tempMilli;
        fs >> tempMilli;
        return tempMilli / 1000; // Convert millidegrees to degrees
    }

    int getCPUTemperature() {
        // Try common thermal zone paths on Android/Linux
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
            if (temp > maxTempFound) {
                maxTempFound = temp;
            }
        }

        return maxTempFound;
    }

public:
    ThermalMonitor(int maxTempC) : maxTemp(maxTempC) {}

    ~ThermalMonitor() {
        stop();
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
                        std::cout << "\n[THERMAL] CPU temperature reached " << currentTemp 
                                  << "°C (max: " << maxTemp << "°C). Pausing for " 
                                  << THERMAL_PAUSE_MINUTES << " minutes...\n";

                        // Pause for THERMAL_PAUSE_MINUTES
                        auto pauseStart = std::chrono::steady_clock::now();
                        while (paused.load() && running.load()) {
                            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::steady_clock::now() - pauseStart).count();

                            if (elapsed >= THERMAL_PAUSE_MINUTES * 60) {
                                paused.store(false);
                                std::cout << "[THERMAL] Pause complete. Resuming search...\n";
                                break;
                            }

                            // Check temp every 5 seconds during pause
                            std::this_thread::sleep_for(std::chrono::seconds(5));
                            int newTemp = getCPUTemperature();
                            if (newTemp >= 0 && newTemp < maxTemp - 5) {
                                // Resume early if temp dropped 5 degrees below threshold
                                paused.store(false);
                                std::cout << "[THERMAL] Temperature dropped to " << newTemp 
                                          << "°C. Resuming early...\n";
                                break;
                            }
                        }
                    }
                }

                // Check temperature every 2 seconds
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
        });
    }

    void stop() {
        running.store(false);
        paused.store(false);
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
    }

    bool isPaused() const {
        return paused.load();
    }

    int getMaxTemp() const {
        return maxTemp;
    }
};

// ============================================================================
// HIGH-PERFORMANCE RANDOM NUMBER GENERATOR
// ============================================================================

struct alignas(64) FastRandom {
    uint64_t s[4];

    explicit FastRandom(uint64_t seed = 1) {
        uint64_t z = seed + 0x9e3779b97f4a7c15ULL;
        s[0] = splitmix64(&z);
        s[1] = splitmix64(&z);
        s[2] = splitmix64(&z);
        s[3] = splitmix64(&z);
        for(int i = 0; i < 20; i++) next();
    }

    static uint64_t splitmix64(uint64_t* x) {
        uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }

    inline uint64_t rotl(uint64_t x, int k) {
        return (x << k) | (x >> (64 - k));
    }

    inline uint64_t next() {
        const uint64_t result = rotl(s[1] * 5, 7) * 9;
        const uint64_t t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = rotl(s[3], 45);
        return result;
    }

    inline uint64_t next_range(uint64_t max) {
        uint64_t mask = max - 1;
        mask |= mask >> 1;
        mask |= mask >> 2;
        mask |= mask >> 4;
        mask |= mask >> 8;
        mask |= mask >> 16;
        mask |= mask >> 32;
        uint64_t r;
        do {
            r = next() & mask;
        } while (r >= max);
        return r;
    }
};

// ============================================================================
// LOCK-FREE BLOOM FILTER (Multiple Targets)
// ============================================================================

class alignas(64) BloomFilter {
private:
    std::vector<std::atomic<uint8_t>> filter;
    std::atomic<size_t> count{0};

    inline uint64_t hash_mix(uint64_t h) const {
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33;
        h *= 0xc4ceb9fe1a85ec53ULL;
        h ^= h >> 33;
        return h;
    }

    inline void hash_bytes(const uint8_t* data, size_t len, uint64_t& h1, uint64_t& h2) const {
        h1 = 0xcbf29ce484222325ULL;
        h2 = 0x84222325cbf29ce4ULL;
        for (size_t i = 0; i < len; i++) {
            h1 ^= data[i];
            h1 *= 0x100000001b3ULL;
            h2 ^= data[i] + 0x9e3779b9;
            h2 = (h2 << 13) | (h2 >> 51);
            h2 *= 0x100000001b3ULL;
        }
        h1 = hash_mix(h1);
        h2 = hash_mix(h2);
    }

public:
    BloomFilter() : filter(BLOOM_FILTER_BITS) {
        for(auto& f : filter) f.store(0, std::memory_order_relaxed);
    }

    void add(const uint8_t* data, size_t len) {
        uint64_t h1, h2;
        hash_bytes(data, len, h1, h2);
        for (int i = 0; i < BLOOM_HASHES; i++) {
            uint64_t h = (h1 + i * h2) % BLOOM_FILTER_BITS;
            filter[h / 8].fetch_or(1 << (h % 8), std::memory_order_relaxed);
        }
        count.fetch_add(1, std::memory_order_relaxed);
    }

    bool test(const uint8_t* data, size_t len) const {
        uint64_t h1, h2;
        hash_bytes(data, len, h1, h2);
        for (int i = 0; i < BLOOM_HASHES; i++) {
            uint64_t h = (h1 + i * h2) % BLOOM_FILTER_BITS;
            if (!(filter[h / 8].load(std::memory_order_relaxed) & (1 << (h % 8)))) {
                return false;
            }
        }
        return true;
    }

    size_t getCount() const { return count.load(); }
};

// ============================================================================
// BATCH HASH160 COMPUTATION
// ============================================================================

class BatchHash160 {
private:
    EVP_MD_CTX* sha_ctx;
    EVP_MD_CTX* ripemd_ctx;

public:
    BatchHash160() {
        sha_ctx = EVP_MD_CTX_new();
        ripemd_ctx = EVP_MD_CTX_new();
    }

    ~BatchHash160() {
        EVP_MD_CTX_free(sha_ctx);
        EVP_MD_CTX_free(ripemd_ctx);
    }

    void compute(const uint8_t pubKeys[][33], uint8_t out[][20], int n) {
        for (int i = 0; i < n; ++i) {
            unsigned int sha_len = SHA256_DIGEST_LENGTH;
            unsigned int ripemd_len = RIPEMD160_DIGEST_LENGTH;
            uint8_t sha_result[SHA256_DIGEST_LENGTH];

            EVP_DigestInit_ex(sha_ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(sha_ctx, pubKeys[i], 33);
            EVP_DigestFinal_ex(sha_ctx, sha_result, &sha_len);

            EVP_DigestInit_ex(ripemd_ctx, EVP_ripemd160(), NULL);
            EVP_DigestUpdate(ripemd_ctx, sha_result, SHA256_DIGEST_LENGTH);
            EVP_DigestFinal_ex(ripemd_ctx, out[i], &ripemd_len);
        }
    }
};

// ============================================================================
// PERFORMANCE COUNTERS (Lock-free)
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
static std::atomic<unsigned long long> g_totalChecked{0};
static std::atomic<unsigned long long> g_totalCandidates{0};
static std::atomic<unsigned long long> g_matchesFound{0};
static std::atomic<bool> g_thermalPaused{false};

static std::string g_foundPrivKey;
static std::string g_foundPubKey;
static std::mutex g_foundMutex;

static std::vector<std::string> g_threadPrivateKeys;
static std::mutex g_outputMutex;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static inline std::string bytesToHex(const uint8_t* data, size_t len) {
    static constexpr char lut[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = data[i];
        out.push_back(lut[b >> 4]);
        out.push_back(lut[b & 0x0F]);
    }
    return out;
}

static inline std::string padHexTo64(const std::string& h) {
    return (h.size() >= 64) ? h : std::string(64 - h.size(), '0') + h;
}

static inline Int hexToInt(const std::string& h) {
    Int n;
    char buf[65] = {0};
    std::strncpy(buf, h.c_str(), 64);
    n.SetBase16(buf);
    return n;
}

static inline std::string intToHex(const Int& v) {
    Int t;
    t.Set((Int*)&v);
    return t.GetBase16();
}

static inline std::string intXToHex64(const Int& x) {
    Int t;
    t.Set((Int*)&x);
    std::string h = t.GetBase16();
    if (h.size() < 64) h.insert(0, 64 - h.size(), '0');
    return h;
}

static inline bool isEven(const Int& n) {
    return n.IsEven();
}

static inline std::string pointToCompressedHex(const Point& p) {
    return (isEven(p.y) ? "02" : "03") + intXToHex64(p.x);
}

static inline void pointToCompressedBin(const Point& p, uint8_t out[33]) {
    out[0] = isEven(p.y) ? 0x02 : 0x03;
    Int t;
    t.Set((Int*)&p.x);
    for (int i = 0; i < 32; ++i)
        out[1 + i] = uint8_t(t.GetByte(31 - i));
}

static void writeFoundKey(const std::string& privHex, const std::string& hash160Hex) {
    std::ofstream ofs("found.txt", std::ios::app);
    if (!ofs) {
        std::cerr << "Cannot open found.txt for writing\n";
        return;
    }
    ofs << "Hash160: " << hash160Hex << "\nPrivate Key: " << privHex << "\n\n";
    ofs.flush();
}

static void appendCandidateToFile(const std::string& privHex, const std::string& hash160Hex) {
    static std::mutex candidatesMutex;
    std::lock_guard<std::mutex> lock(candidatesMutex);
    std::ofstream ofs("candidates.txt", std::ios::app);
    if (ofs) {
        ofs << "Private Key: " << privHex << "\nHash160: " << hash160Hex << "\n\n";
        ofs.flush();
    }
}

static std::string formatElapsedTime(double sec) {
    int h = int(sec) / 3600, m = (int(sec) % 3600) / 60, s = int(sec) % 60;
    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << h << ":"
        << std::setw(2) << m << ":"
        << std::setw(2) << s;
    return oss.str();
}

static std::string formatLargeNumber(unsigned long long num) {
    std::string str = std::to_string(num);
    std::string result;
    int count = 0;
    for (int i = str.length() - 1; i >= 0; i--) {
        if (count == 3) {
            result = "," + result;
            count = 0;
        }
        result = str[i] + result;
        count++;
    }
    return result;
}

// ============================================================================
// RANDOM INT GENERATION
// ============================================================================

static inline void generateRandomIntInRange(const Int& start, const Int& rangeSize, 
                                             Int& result, FastRandom& rng) {
    uint64_t data[4];
    for(int i = 0; i < 4; i++) {
        data[i] = rng.next();
    }

    result.SetInt32(0);
    for(int i = 0; i < 4; i++) {
        Int temp;
        temp.SetInt32(uint32_t(data[i]));
        temp.ShiftL(32 * i);
        result.Add(&temp);

        temp.SetInt32(uint32_t(data[i] >> 32));
        temp.ShiftL(32 * (i + 4));
        result.Add(&temp);
    }

    Int rangeCopy;
    rangeCopy.Set((Int*)&rangeSize);
    result.Mod(&rangeCopy);

    Int startCopy;
    startCopy.Set((Int*)&start);
    result.Add(&startCopy);
}

// ============================================================================
// MAIN HUNTER CLASS
// ============================================================================

class PuzzleHunter {
public:
    std::vector<std::vector<uint8_t>> targetHash160s;

private:
    Secp256K1 secp;
    Int startRange, endRange, rangeSize;
    std::unique_ptr<BloomFilter> bloom;
    int numThreads;
    int statIntervalMs;
    ThermalMonitor* thermalMonitor;

public:
    PuzzleHunter(int statMs = DEFAULT_STAT_INTERVAL_MS, ThermalMonitor* therm = nullptr) 
        : statIntervalMs(statMs), thermalMonitor(therm) {
        secp.Init();
        numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4;
    }

    void addTarget(const std::string& hash160Hex) {
        std::vector<uint8_t> hash(20);
        for (int i = 0; i < 20; i++) {
            sscanf(hash160Hex.c_str() + 2 * i, "%02hhx", &hash[i]);
        }
        targetHash160s.push_back(hash);
    }

    void setRange(const std::string& startHex, const std::string& endHex) {
        startRange = hexToInt(startHex);
        endRange = hexToInt(endHex);
        rangeSize.Sub(&endRange, &startRange);
    }

    void initialize() {
        bloom = std::make_unique<BloomFilter>();
        for (const auto& target : targetHash160s) {
            bloom->add(target.data(), 20);
        }
    }

    void workerThread(int tid, ThreadStats& stats) {
        FastRandom rng((uint64_t)(tid + 1) * 0x9e3779b97f4a7c15ULL + 
                      (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count());

        std::vector<Int> batchPrivKeys(POINTS_BATCH_SIZE);
        std::vector<Point> ptBatch(POINTS_BATCH_SIZE);

        BatchHash160 hasher;
        uint8_t pubKeys[HASH_BATCH_SIZE][33];
        uint8_t hashRes[HASH_BATCH_SIZE][20];

        unsigned long long localChecked = 0;
        unsigned long long localCandidates = 0;

        while (!g_matchFound.load(std::memory_order_relaxed)) {
            // Check thermal pause
            if (thermalMonitor && thermalMonitor->isPaused()) {
                g_thermalPaused.store(true);
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            g_thermalPaused.store(false);

            // Generate random private keys in batch
            for (int i = 0; i < POINTS_BATCH_SIZE; ++i) {
                generateRandomIntInRange(startRange, rangeSize, batchPrivKeys[i], rng);
            }

            if (localChecked % 10000 == 0) {
                g_threadPrivateKeys[tid] = padHexTo64(intToHex(batchPrivKeys[0]));
            }

            secp.ComputePublicKeyBatch(batchPrivKeys.data(), POINTS_BATCH_SIZE, ptBatch.data());

            for (int batchStart = 0; batchStart < POINTS_BATCH_SIZE; batchStart += HASH_BATCH_SIZE) {
                int batchEnd = std::min(batchStart + HASH_BATCH_SIZE, POINTS_BATCH_SIZE);
                int batchSize = batchEnd - batchStart;

                for (int i = 0; i < batchSize; ++i) {
                    pointToCompressedBin(ptBatch[batchStart + i], pubKeys[i]);
                }

                hasher.compute(pubKeys, hashRes, batchSize);

                for (int i = 0; i < batchSize; ++i) {
                    ++localChecked;

                    if (!bloom->test(hashRes[i], 20)) {
                        continue;
                    }

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
                localChecked = 0;
                localCandidates = 0;
            }
        }

        stats.checked.fetch_add(localChecked, std::memory_order_relaxed);
        stats.candidates.fetch_add(localCandidates, std::memory_order_relaxed);
        g_totalChecked.fetch_add(localChecked, std::memory_order_relaxed);
        g_totalCandidates.fetch_add(localCandidates, std::memory_order_relaxed);
    }

    void run() {
        g_threadPrivateKeys.assign(numThreads, "0");
        std::vector<ThreadStats> threadStats(numThreads);

        auto tStart = std::chrono::high_resolution_clock::now();

        std::vector<std::thread> threads;
        for (int tid = 0; tid < numThreads; ++tid) {
            threads.emplace_back([this, tid, &threadStats]() {
                this->workerThread(tid, threadStats[tid]);
            });
        }

        // Statistics display thread
        std::thread statThread([this, tStart, &threadStats]() {
            while (!g_matchFound.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(statIntervalMs));

                auto now = std::chrono::high_resolution_clock::now();
                double elapsed = std::chrono::duration<double>(now - tStart).count();
                unsigned long long total = g_totalChecked.load();
                double kps = total / elapsed;

                unsigned long long threadTotal = 0;
                for (int i = 0; i < numThreads; i++) {
                    threadTotal += threadStats[i].checked.load();
                }

                std::string thermalStatus = "";
                if (g_thermalPaused.load()) {
                    thermalStatus = " [THERMAL PAUSE]";
                }

                system("clear");
                std::cout << "╔══════════════════════════════════════════════════════════════╗\n"
                          << "║         BTC PUZZLE HUNTER v2.1 - ARM64 OPTIMIZED            ║\n"
                          << "╠══════════════════════════════════════════════════════════════╣\n"
                          << "║ Threads:    " << std::setw(3) << numThreads 
                          << " / " << std::setw(3) << std::thread::hardware_concurrency() << " active          ║\n"
                          << "║ Keys/sec:   " << std::setw(12) << std::fixed << std::setprecision(0) << kps << "              ║\n"
                          << "║ Total:      " << std::setw(18) << formatLargeNumber(total) << "        ║\n"
                          << "║ Elapsed:    " << std::setw(10) << formatElapsedTime(elapsed) << "                  ║\n"
                          << "║ Candidates: " << std::setw(8) << g_totalCandidates.load() << "                        ║\n"
                          << "║ Matches:    " << std::setw(8) << g_matchesFound.load() << "                        ║\n"
                          << "║ Refresh:    " << std::setw(6) << statIntervalMs << " ms" << std::setw(18) << ""
                          << thermalStatus << std::setw(20 - thermalStatus.length()) << "║\n"
                          << "╚══════════════════════════════════════════════════════════════╝\n";
            }
        });

        for (auto& t : threads) {
            t.join();
        }
        g_matchFound.store(true);
        statThread.join();

        auto tEnd = std::chrono::high_resolution_clock::now();
        double totalElapsed = std::chrono::duration<double>(tEnd - tStart).count();

        system("clear");
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
                      << "║ Total checked: " << std::setw(18) << formatLargeNumber(g_totalChecked.load()) << "       ║\n"
                      << "║ Time:         " << std::setw(10) << formatElapsedTime(totalElapsed) << "                  ║\n"
                      << "║ Avg k/s:      " << std::setw(12) << std::fixed << std::setprecision(0) 
                      << (g_totalChecked.load() / totalElapsed) << "              ║\n"
                      << "╚══════════════════════════════════════════════════════════════╝\n";
        }
    }
};

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int main(int argc, char* argv[]) {
    CliArgs args = parseArgs(argc, argv);

    if (args.help) {
        printUsage(argv[0]);
        return 0;
    }

    if (!args.valid) {
        std::cerr << "Error: " << args.errorMsg << "\n\n";
        printUsage(argv[0]);
        return 1;
    }

    std::cout << "╔══════════════════════════════════════════════════════════════╗\n"
              << "║     Bitcoin Puzzle Hunter v2.1 - ARM64 Optimized               ║\n"
              << "║     CLI Edition with Thermal Management                        ║\n"
              << "╚══════════════════════════════════════════════════════════════╝\n\n";

    std::cout << "[CONFIG] Range: " << args.startRange << " to " << args.endRange << "\n";
    std::cout << "[CONFIG] Targets: " << args.targetHash160s.size() << "\n";
    std::cout << "[CONFIG] Max Temp: " << args.maxTemp << "°C\n";
    std::cout << "[CONFIG] Stat Interval: " << args.statIntervalMs << " ms\n";
    std::cout << "[CONFIG] Threads: " << std::thread::hardware_concurrency() << "\n\n";

    OpenSSL_add_all_algorithms();

    // Start thermal monitor
    ThermalMonitor thermalMonitor(args.maxTemp);
    thermalMonitor.start();

    PuzzleHunter hunter(args.statIntervalMs, &thermalMonitor);

    // Add targets from CLI
    for (const auto& hash : args.targetHash160s) {
        hunter.addTarget(hash);
    }

    hunter.setRange(args.startRange, args.endRange);
    hunter.initialize();

    std::cout << "Starting optimized search...\n";
    std::this_thread::sleep_for(std::chrono::seconds(1));

    hunter.run();

    // Stop thermal monitor
    thermalMonitor.stop();

    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}
