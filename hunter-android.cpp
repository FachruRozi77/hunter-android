// ============================================================================
// BTC PUZZLE HUNTER v2.0 - ARM Optimized
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
static constexpr int STAT_INTERVAL_MS = 500;        // Sub-second updates
static constexpr int SAVE_INTERVAL_SEC = 60;        // More frequent saves

// Bloom filter - sized for multiple targets (1000 puzzle addresses)
static constexpr size_t BLOOM_FILTER_BITS = 1 << 24;  // 16MB for low false positive
static constexpr int BLOOM_HASHES = 12;

// Threading
static constexpr int MAX_THREADS = 256;              // Allow all cores including SMT

// ============================================================================
// HIGH-PERFORMANCE RANDOM NUMBER GENERATOR
// ============================================================================

// xoshiro256** - fastest high-quality PRNG for ARM64
struct alignas(64) FastRandom {
    uint64_t s[4];
    
    explicit FastRandom(uint64_t seed = 1) {
        // SplitMix64 seeding
        uint64_t z = seed + 0x9e3779b97f4a7c15ULL;
        s[0] = splitmix64(&z);
        s[1] = splitmix64(&z);
        s[2] = splitmix64(&z);
        s[3] = splitmix64(&z);
        // Warmup
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
    
    // Generate 64-bit value in range [0, max)
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
    
    // MurmurHash3-inspired hash functions optimized for ARM
    inline uint64_t hash_mix(uint64_t h) const {
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33;
        h *= 0xc4ceb9fe1a85ec53ULL;
        h ^= h >> 33;
        return h;
    }
    
    inline void hash_bytes(const uint8_t* data, size_t len, uint64_t& h1, uint64_t& h2) const {
        // FNV-1a variant
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
// BATCH HASH160 COMPUTATION (SIMD-Optimized)
// ============================================================================

// Structure for batch hash computation
struct HashBatch {
    alignas(64) uint8_t pubKeys[HASH_BATCH_SIZE][33];
    alignas(64) uint8_t hashResults[HASH_BATCH_SIZE][20];
    int count;
};

// Optimized batch hash160 using OpenSSL with context reuse
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
    
    // Process batch of compressed public keys to hash160
    void compute(const uint8_t pubKeys[][33], uint8_t out[][20], int n) {
        for (int i = 0; i < n; ++i) {
            // SHA256
            unsigned int sha_len = SHA256_DIGEST_LENGTH;
            unsigned int ripemd_len = RIPEMD160_DIGEST_LENGTH;
            uint8_t sha_result[SHA256_DIGEST_LENGTH];
            
            EVP_DigestInit_ex(sha_ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(sha_ctx, pubKeys[i], 33);
            EVP_DigestFinal_ex(sha_ctx, sha_result, &sha_len);
            
            // RIPEMD160
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
// RANDOM INT GENERATION (Optimized for 256-bit keys)
// ============================================================================

static inline void generateRandomIntInRange(const Int& start, const Int& rangeSize, 
                                             Int& result, FastRandom& rng) {
    // Generate 256 random bits directly
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
    
    // Reduce to range
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
private:
    Secp256K1 secp;
    Int startRange, endRange, rangeSize;
    std::vector<std::vector<uint8_t>> targetHash160s;
    std::unique_ptr<BloomFilter> bloom;
    int numThreads;
    
public:
    PuzzleHunter() {
        secp.Init();
        numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4;
        std::cout << "[INFO] Detected " << numThreads << " hardware threads\n";
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
        std::cout << "[INFO] Bloom filter initialized with " << targetHash160s.size() 
                  << " targets, count=" << bloom->getCount() << "\n";
    }
    
    void workerThread(int tid, ThreadStats& stats) {
        // Thread-local RNG with unique seed
        FastRandom rng((uint64_t)(tid + 1) * 0x9e3779b97f4a7c15ULL + 
                      (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count());
        
        // Pre-allocate all buffers
        std::vector<Int> batchPrivKeys(POINTS_BATCH_SIZE);
        std::vector<Point> ptBatch(POINTS_BATCH_SIZE);
        
        // Hash batch processor
        BatchHash160 hasher;
        uint8_t pubKeys[HASH_BATCH_SIZE][33];
        uint8_t hashRes[HASH_BATCH_SIZE][20];
        
        unsigned long long localChecked = 0;
        unsigned long long localCandidates = 0;
        
        while (!g_matchFound.load(std::memory_order_relaxed)) {
            // Generate random private keys in batch
            for (int i = 0; i < POINTS_BATCH_SIZE; ++i) {
                generateRandomIntInRange(startRange, rangeSize, batchPrivKeys[i], rng);
            }
            
            // Update thread's current key (for progress tracking)
            if (localChecked % 10000 == 0) {
                g_threadPrivateKeys[tid] = padHexTo64(intToHex(batchPrivKeys[0]));
            }
            
            // Compute public keys with batch inversion
            secp.ComputePublicKeyBatch(batchPrivKeys.data(), POINTS_BATCH_SIZE, ptBatch.data());
            
            // Process in hash-sized batches
            for (int batchStart = 0; batchStart < POINTS_BATCH_SIZE; batchStart += HASH_BATCH_SIZE) {
                int batchEnd = std::min(batchStart + HASH_BATCH_SIZE, POINTS_BATCH_SIZE);
                int batchSize = batchEnd - batchStart;
                
                // Convert to compressed format
                for (int i = 0; i < batchSize; ++i) {
                    pointToCompressedBin(ptBatch[batchStart + i], pubKeys[i]);
                }
                
                // Compute hash160 batch
                hasher.compute(pubKeys, hashRes, batchSize);
                
                // Check results
                for (int i = 0; i < batchSize; ++i) {
                    ++localChecked;
                    
                    // Bloom filter first
                    if (!bloom->test(hashRes[i], 20)) {
                        continue;
                    }
                    
                    // Candidate found - check all targets
                    std::string hash160Hex = bytesToHex(hashRes[i], 20);
                    Int& actualPrivKey = batchPrivKeys[batchStart + i];
                    std::string privHex = padHexTo64(intToHex(actualPrivKey));
                    
                    appendCandidateToFile(privHex, hash160Hex);
                    ++localCandidates;
                    
                    // Check exact match against all targets
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
            
            // Update stats periodically (lock-free)
            if (localChecked % 10000 == 0) {
                stats.checked.fetch_add(localChecked, std::memory_order_relaxed);
                stats.candidates.fetch_add(localCandidates, std::memory_order_relaxed);
                g_totalChecked.fetch_add(localChecked, std::memory_order_relaxed);
                g_totalCandidates.fetch_add(localCandidates, std::memory_order_relaxed);
                localChecked = 0;
                localCandidates = 0;
            }
        }
        
        // Final stats update
        stats.checked.fetch_add(localChecked, std::memory_order_relaxed);
        stats.candidates.fetch_add(localCandidates, std::memory_order_relaxed);
        g_totalChecked.fetch_add(localChecked, std::memory_order_relaxed);
        g_totalCandidates.fetch_add(localCandidates, std::memory_order_relaxed);
    }
    
    void run() {
        // Initialize thread tracking
        g_threadPrivateKeys.assign(numThreads, "0");
        std::vector<ThreadStats> threadStats(numThreads);
        
        auto tStart = std::chrono::high_resolution_clock::now();
        auto lastStat = tStart;
        
        // Launch worker threads
        std::vector<std::thread> threads;
        for (int tid = 0; tid < numThreads; ++tid) {
            threads.emplace_back([this, tid, &threadStats]() {
                this->workerThread(tid, threadStats[tid]);
            });
        }
        
        // Statistics display thread
        std::thread statThread([this, tStart, &threadStats]() {
            auto lastStat = std::chrono::high_resolution_clock::now();
            while (!g_matchFound.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(STAT_INTERVAL_MS));
                
                auto now = std::chrono::high_resolution_clock::now();
                double elapsed = std::chrono::duration<double>(now - tStart).count();
                unsigned long long total = g_totalChecked.load();
                double kps = total / elapsed;
                
                // Gather per-thread stats
                unsigned long long threadTotal = 0;
                for (int i = 0; i < numThreads; i++) {
                    threadTotal += threadStats[i].checked.load();
                }
                
                // Clear screen and print
                system("clear");
                std::cout << "╔══════════════════════════════════════════════════════════════╗\n"
                          << "║         BTC PUZZLE HUNTER v2.0 - ARM64 OPTIMIZED            ║\n"
                          << "╠══════════════════════════════════════════════════════════════╣\n"
                          << "║ Threads:    " << std::setw(3) << numThreads 
                          << " / " << std::setw(3) << std::thread::hardware_concurrency() << " active          ║\n"
                          << "║ Keys/sec:   " << std::setw(12) << std::fixed << std::setprecision(0) << kps << "              ║\n"
                          << "║ Total:      " << std::setw(18) << formatLargeNumber(total) << "        ║\n"
                          << "║ Elapsed:    " << std::setw(10) << formatElapsedTime(elapsed) << "                  ║\n"
                          << "║ Candidates: " << std::setw(8) << g_totalCandidates.load() << "                        ║\n"
                          << "║ Matches:    " << std::setw(8) << g_matchesFound.load() << "                        ║\n"
                          << "╚══════════════════════════════════════════════════════════════╝\n";
            }
        });
        
        // Wait for completion
        for (auto& t : threads) {
            t.join();
        }
        g_matchFound.store(true); // Signal stat thread to stop
        statThread.join();
        
        // Final display
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

int main() {
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n"
              << "║     Bitcoin Puzzle Hunter v2.0 - ARM64 Optimized               ║\n"
              << "║     Maximum Performance Edition for 1000 BTC Puzzle            ║\n"
              << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    OpenSSL_add_all_algorithms();
    
    PuzzleHunter hunter;
    
    // Get all puzzle addresses
    std::cout << "Enter puzzle target hash160 addresses (one per line, empty line to finish):\n";
    std::cout << "Example: 739437bb8dd3b9e8c6f0e2f3b8a1c5d7e9f2b4a6\n";
    
    std::string input;
    while (true) {
        std::cout << "Target #" << (hunter.targetHash160s.size() + 1) << ": ";
        std::getline(std::cin, input);
        if (input.empty()) break;
        
        // Remove whitespace
        input.erase(std::remove_if(input.begin(), input.end(), ::isspace), input.end());
        
        if (input.length() != 40) {
            std::cerr << "Error: Hash160 must be exactly 40 hex characters\n";
            continue;
        }
        hunter.addTarget(input);
    }
    
    if (hunter.targetHash160s.empty()) {
        std::cerr << "Error: At least one target required\n";
        return 1;
    }
    
    // Get range
    std::string startHex, endHex;
    std::cout << "\nEnter start range (hex): ";
    std::getline(std::cin, startHex);
    std::cout << "Enter end range (hex): ";
    std::getline(std::cin, endHex);
    
    if (startHex.empty() || endHex.empty()) {
        std::cerr << "Error: Range required\n";
        return 1;
    }
    
    hunter.setRange(startHex, endHex);
    hunter.initialize();
    
    std::cout << "\nStarting optimized search with " << hunter.targetHash160s.size() 
              << " targets...\n";
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    hunter.run();
    
    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}
