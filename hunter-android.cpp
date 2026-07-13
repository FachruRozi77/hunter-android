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

// OpenSSL includes for crypto functions
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>

// Conditional OpenMP support
#ifdef _OPENMP
#include <omp.h>
#define USE_OPENMP 1
#else
#define USE_OPENMP 0
#define omp_get_num_procs() std::thread::hardware_concurrency()
#define omp_get_thread_num() 0
#endif

// Include SECP256K1 headers (assuming they're ARM-compatible)
#include "SECP256K1.h"
#include "Point.h"
#include "Int.h"
#include "IntGroup.h"

// Configuration constants (optimized for mobile)
static constexpr int    POINTS_BATCH_SIZE       = 1024;  // Increased for better performance
static constexpr int    HASH_BATCH_SIZE         = 8;     // Increased back to 8
static constexpr double STATUS_INTERVAL_SEC     = 3.0;   // More frequent updates
static constexpr double SAVE_PROGRESS_INTERVAL  = 300.0;
static constexpr size_t BLOOM_FILTER_SIZE       = 1 << 19; // 512KB 
static constexpr int    BLOOM_HASHES            = 8;

// Fast random number generator (ARM-compatible xoshiro256**)
struct FastRandom {
    uint64_t s[4];
    
    FastRandom(uint64_t seed = 1) {
        s[0] = seed;
        s[1] = seed ^ 0x9E3779B97F4A7C15ULL;
        s[2] = seed ^ 0xBF58476D1CE4E5B9ULL;
        s[3] = seed ^ 0x94D049BB133111EBULL;
        // Warm up
        for(int i = 0; i < 20; i++) next();
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
};

// Thread-local fast random generators
static thread_local FastRandom g_fastRng;

// Global variables
static std::mutex                   g_outputMutex;
static std::atomic<unsigned long long> g_candidatesFound{0};
static std::atomic<unsigned long long> g_totalChecked{0};
static std::atomic<unsigned long long> g_matchesFound{0};
static std::vector<std::string>     g_threadPrivateKeys;
static std::atomic<bool>            g_matchFound{false};
static std::string                  g_foundPrivKey;
static std::string                  g_foundPubKey;

// Optimized Bloom Filter for ARM
class BloomFilter {
private:
    std::vector<uint8_t> filter;
    std::atomic<int> count;
    
    // Fast hash functions optimized for ARM
    inline uint32_t hash1(const uint8_t* data, size_t len) const {
        uint32_t hash = 0x811c9dc5; // FNV offset basis
        for (size_t i = 0; i < len; i++) {
            hash ^= data[i];
            hash *= 0x01000193; // FNV prime
        }
        return hash;
    }
    
    inline uint32_t hash2(const uint8_t* data, size_t len) const {
        uint32_t hash = 0;
        for (size_t i = 0; i < len; i++) {
            hash = ((hash << 5) + hash) + data[i]; // djb2 hash
        }
        return hash;
    }

public:
    BloomFilter() : filter(BLOOM_FILTER_SIZE, 0), count(0) {}

    void add(const uint8_t* data, size_t len) {
        uint32_t h1 = hash1(data, len);
        uint32_t h2 = hash2(data, len);
        
        for (int i = 0; i < BLOOM_HASHES; i++) {
            uint32_t h = (h1 + i * h2) % (BLOOM_FILTER_SIZE * 8);
            filter[h / 8] |= (1 << (h % 8));
        }
        count++;
    }

    bool test(const uint8_t* data, size_t len) const {
        uint32_t h1 = hash1(data, len);
        uint32_t h2 = hash2(data, len);
        
        for (int i = 0; i < BLOOM_HASHES; i++) {
            uint32_t h = (h1 + i * h2) % (BLOOM_FILTER_SIZE * 8);
            if (!(filter[h / 8] & (1 << (h % 8)))) {
                return false;
            }
        }
        return true;
    }

    int getCount() const { return count.load(); }
};

// Helper functions
static inline std::string bytesToHex(const uint8_t* data, size_t len)
{
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

static void writeFoundKey(const std::string& privHex, const std::string& hash160Hex)
{
    std::ofstream ofs("found.txt", std::ios::app);
    if (!ofs) {
        std::cerr << "Cannot open found.txt for writing\n";
        return;
    }
    ofs << "Hash160: " << hash160Hex << "\nPrivate Key: " << privHex << "\n\n";
    ofs.flush();
}

static void appendCandidateToFile(const std::string& privHex, const std::string& hash160Hex)
{
    g_candidatesFound++;
    
    static std::mutex candidatesMutex;
    std::lock_guard<std::mutex> lock(candidatesMutex);
    std::ofstream ofs("pb.txt", std::ios::app);
    if (ofs) {
        ofs << "Private Key: " << privHex << "\nHash160: " << hash160Hex << "\n\n";
        ofs.flush();
    } else {
        std::cerr << "Cannot open pb.txt for writing\n";
    }
}

static inline std::string padHexTo64(const std::string& h)
{
    return (h.size() >= 64) ? h : std::string(64 - h.size(), '0') + h;
}

static inline Int hexToInt(const std::string& h)
{
    Int n; 
    char buf[65] = {0};
    std::strncpy(buf, h.c_str(), 64);
    n.SetBase16(buf);
    return n;
}

static inline std::string intToHex(const Int& v)
{
    Int t; 
    t.Set((Int*)&v); 
    return t.GetBase16();
}

static inline std::string intXToHex64(const Int& x)
{
    Int t; 
    t.Set((Int*)&x);
    std::string h = t.GetBase16();
    if (h.size() < 64) h.insert(0, 64 - h.size(), '0');
    return h;
}

static inline bool isEven(const Int& n) { 
    return n.IsEven(); 
}

static inline std::string pointToCompressedHex(const Point& p)
{
    return (isEven(p.y) ? "02" : "03") + intXToHex64(p.x);
}

static inline void pointToCompressedBin(const Point& p, uint8_t out[33])
{
    out[0] = isEven(p.y) ? 0x02 : 0x03;
    Int t; 
    t.Set((Int*)&p.x);
    for (int i = 0; i < 32; ++i)
        out[1 + i] = uint8_t(t.GetByte(31 - i));
}

// Optimized random Int generation within range
static inline void generateRandomIntInRange(const Int& start, const Int& rangeSize, Int& result, FastRandom& rng)
{
    // Generate random bytes directly into the Int (optimized for 256-bit keys)
    uint32_t data[8]; // 256 bits
    for(int i = 0; i < 4; i++) {
        uint64_t rnd = rng.next();
        data[i*2] = uint32_t(rnd);
        data[i*2+1] = uint32_t(rnd >> 32);
    }
    
    result.SetInt32(0);
    for(int i = 0; i < 8; i++) {
        Int temp;
        temp.SetInt32(data[i]);
        uint32_t shiftAmount = 32 * i;
        temp.ShiftL(shiftAmount);
        result.Add(&temp);
    }
    
    // Create mutable copies for Mod and Add operations
    Int rangeCopy;
    rangeCopy.Set((Int*)&rangeSize);
    result.Mod(&rangeCopy);
    
    Int startCopy;
    startCopy.Set((Int*)&start);
    result.Add(&startCopy);
}

// Optimized hash computation using OpenSSL
static inline void computeHash160Simple(const uint8_t* pubKey, uint8_t* hash160)
{
    // Step 1: SHA256 of public key
    uint8_t sha256_result[SHA256_DIGEST_LENGTH];
    SHA256(pubKey, 33, sha256_result);
    
    // Step 2: RIPEMD160 of SHA256 result
    RIPEMD160(sha256_result, SHA256_DIGEST_LENGTH, hash160);
}

// Batch processing with OpenSSL EVP (more efficient)
static void computeHash160BatchOptimized(int nKeys,
                                       uint8_t pub[][33],
                                       uint8_t outHash[][20])
{
    // Pre-allocate contexts for better performance
    EVP_MD_CTX* sha_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX* ripemd_ctx = EVP_MD_CTX_new();
    
    if (!sha_ctx || !ripemd_ctx) {
        std::cerr << "Failed to create OpenSSL contexts\n";
        // Fallback to simple method
        for (int i = 0; i < nKeys; ++i) {
            computeHash160Simple(pub[i], outHash[i]);
        }
        if (sha_ctx) EVP_MD_CTX_free(sha_ctx);
        if (ripemd_ctx) EVP_MD_CTX_free(ripemd_ctx);
        return;
    }
    
    for (int i = 0; i < nKeys; ++i) {
        uint8_t sha256_result[SHA256_DIGEST_LENGTH];
        unsigned int sha_len = SHA256_DIGEST_LENGTH;
        unsigned int ripemd_len = RIPEMD160_DIGEST_LENGTH;
        
        // SHA256
        if (EVP_DigestInit_ex(sha_ctx, EVP_sha256(), NULL) != 1 ||
            EVP_DigestUpdate(sha_ctx, pub[i], 33) != 1 ||
            EVP_DigestFinal_ex(sha_ctx, sha256_result, &sha_len) != 1) {
            // Fallback to simple method for this key
            computeHash160Simple(pub[i], outHash[i]);
            continue;
        }
        
        // RIPEMD160
        if (EVP_DigestInit_ex(ripemd_ctx, EVP_ripemd160(), NULL) != 1 ||
            EVP_DigestUpdate(ripemd_ctx, sha256_result, SHA256_DIGEST_LENGTH) != 1 ||
            EVP_DigestFinal_ex(ripemd_ctx, outHash[i], &ripemd_len) != 1) {
            // Fallback to simple method for this key
            computeHash160Simple(pub[i], outHash[i]);
            continue;
        }
    }
    
    EVP_MD_CTX_free(sha_ctx);
    EVP_MD_CTX_free(ripemd_ctx);
}

static std::string formatElapsedTime(double sec)
{
    int h = int(sec) / 3600, m = (int(sec) % 3600) / 60, s = int(sec) % 60;
    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << h << ":"
        << std::setw(2) << m << ":"
        << std::setw(2) << s;
    return oss.str();
}

static std::string formatLargeNumber(unsigned long long num)
{
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

static void printStats(int nCPU,
                       const std::string& targetHash160,
                       double kps,
                       unsigned long long checked,
                       double elapsed,
                       unsigned long long candCnt,
                       unsigned long long matchCnt)
{
    // Clear screen for better mobile display
    system("clear");
    
    std::cout << "╔══════════════════════════════════════════════════════╗\n"
              << "║                TERMUX BTC HUNTER                     ║\n"
              << "╠══════════════════════════════════════════════════════╣\n"
              << "║ Target Hash160: " << targetHash160 << " ║\n"
              << "║ CPU Threads   : " << std::setw(2) << nCPU << "                                   ║\n"
              << "║ Keys/sec      : " << std::setw(12) << std::fixed << std::setprecision(0) << kps << "                           ║\n"
              << "║ Total Checked : " << std::setw(15) << formatLargeNumber(checked) << "                        ║\n"
              << "║ Elapsed Time  : " << std::setw(8) << formatElapsedTime(elapsed) << "                             ║\n"
              << "║ Candidates    : " << std::setw(8) << candCnt << "                             ║\n"
              << "║ Matches Found : " << std::setw(8) << matchCnt << "                             ║\n"
              << "║ Platform      : Android/Termux                      ║\n"
              << "╚══════════════════════════════════════════════════════╝\n";
    std::cout.flush();
}

int main()
{
    std::cout << "╔══════════════════════════════════════════════════════╗\n"
              << "║        Termux Bitcoin Private Key Hunter             ║\n"
              << "║           ARM-Compatible Random Search               ║\n"
              << "║              with OpenSSL Crypto                     ║\n"
              << "╚══════════════════════════════════════════════════════╝\n\n";

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();

    // Get input parameters
    std::string startHex, endHex, targetHash160;
    
    std::cout << "Enter start range (hex): ";
    std::getline(std::cin, startHex);
    
    std::cout << "Enter end range (hex): ";
    std::getline(std::cin, endHex);
    
    std::cout << "Enter target hash160 (40 hex chars): ";
    std::getline(std::cin, targetHash160);

    // Validate inputs
    if (startHex.empty() || endHex.empty() || targetHash160.empty()) {
        std::cerr << "Error: All fields are required\n";
        return 1;
    }

    if (targetHash160.length() != 40) {
        std::cerr << "Error: Hash160 must be exactly 40 hexadecimal characters\n";
        return 1;
    }

    // Convert target hash160 to binary
    std::vector<uint8_t> targetHash160Bin(20);
    for (int i = 0; i < 20; i++) {
        if (sscanf(targetHash160.c_str() + 2 * i, "%02hhx", &targetHash160Bin[i]) != 1) {
            std::cerr << "Error: Invalid hexadecimal in hash160\n";
            return 1;
        }
    }

    // Initialize bloom filter with target
    BloomFilter bloom;
    bloom.add(targetHash160Bin.data(), 20);

    // Initialize range
    Int startRange = hexToInt(startHex);
    Int endRange = hexToInt(endHex);
    Int rangeSize;
    rangeSize.Sub(&endRange, &startRange);

    // Initialize threading (limit for mobile)
    int numCPUs = std::thread::hardware_concurrency();
    if (numCPUs > 6) numCPUs = 6; // Limit threads on mobile to prevent overheating
    g_threadPrivateKeys.assign(numCPUs, "0");

    std::atomic<unsigned long long> globalChecked{0};
    double globalElapsed = 0.0, kps = 0.0;
    auto tStart = std::chrono::high_resolution_clock::now();
    auto lastStat = tStart;

    // Initialize secp256k1
    Secp256K1 secp;
    secp.Init();

    std::cout << "\n[SYSTEM] Using " << numCPUs << " threads on Android ARM\n";
    std::cout << "Target Hash160: " << targetHash160 << "\n";
    std::cout << "Range: " << startHex << " to " << endHex << "\n";
    std::cout << "Starting optimized random search...\n\n";
    
    std::this_thread::sleep_for(std::chrono::seconds(2)); // Give user time to read

    // Create worker threads
    std::vector<std::thread> threads;
    
    for (int tid = 0; tid < numCPUs; ++tid) {
        threads.emplace_back([&, tid]() {
            // Initialize thread-local fast RNG
            g_fastRng = FastRandom((uint64_t)(tid + 1) * (uint64_t)time(NULL) + tid * 12345);

            // Thread-local variables
            std::vector<Int> batchPrivKeys(POINTS_BATCH_SIZE);
            std::vector<Point> ptBatch(POINTS_BATCH_SIZE);
            
            uint8_t pubKeys[HASH_BATCH_SIZE][33];
            uint8_t hashRes[HASH_BATCH_SIZE][20];
            
            unsigned long long localChecked = 0ULL;

            while (!g_matchFound.load(std::memory_order_relaxed)) {
                // Generate random private keys in batch
                for (int i = 0; i < POINTS_BATCH_SIZE; ++i) {
                    generateRandomIntInRange(startRange, rangeSize, batchPrivKeys[i], g_fastRng);
                }

                // Store current private key for this thread (less frequently for performance)
                if (localChecked % 5000 == 0) {
                    g_threadPrivateKeys[tid] = padHexTo64(intToHex(batchPrivKeys[0]));
                }

                // Compute public keys
                ptBatch.resize(POINTS_BATCH_SIZE);
                for(size_t i = 0; i < POINTS_BATCH_SIZE; i++) {
                    ptBatch[i] = secp.ComputePublicKey(&batchPrivKeys[i]);
                }

                // Process points in smaller batches for hashing
                for (int batchStart = 0; batchStart < POINTS_BATCH_SIZE; batchStart += HASH_BATCH_SIZE) {
                    int batchEnd = std::min(batchStart + HASH_BATCH_SIZE, POINTS_BATCH_SIZE);
                    int batchSize = batchEnd - batchStart;

                    // Convert points to compressed public keys
                    for (int i = 0; i < batchSize; ++i) {
                        pointToCompressedBin(ptBatch[batchStart + i], pubKeys[i]);
                    }

                    // Compute hash160 for batch using optimized OpenSSL
                    computeHash160BatchOptimized(batchSize, pubKeys, hashRes);

                    // Check results
                    for (int i = 0; i < batchSize; ++i) {
                        ++localChecked;

                        // Fast bloom filter check first
                        if (!bloom.test(hashRes[i], 20)) {
                            continue;
                        }

                        // Bloom filter passed - this is a candidate
                        std::string hash160Hex = bytesToHex(hashRes[i], 20);
                        Int& actualPrivKey = batchPrivKeys[batchStart + i];
                        
                        appendCandidateToFile(
                            padHexTo64(intToHex(actualPrivKey)),
                            hash160Hex
                        );

                        // Check if it's an exact match
                        if (std::memcmp(hashRes[i], targetHash160Bin.data(), 20) == 0) {
                            bool expected = false;
                            if (g_matchFound.compare_exchange_strong(expected, true)) {
                                g_foundPrivKey = padHexTo64(intToHex(actualPrivKey));
                                g_foundPubKey = pointToCompressedHex(ptBatch[batchStart + i]);
                                g_matchesFound++;
                            }
                            return;
                        }
                    }
                }

                // Update statistics (less frequent for better performance)
                if (localChecked % 5000 == 0) {
                    auto now = std::chrono::high_resolution_clock::now();
                    if (std::chrono::duration<double>(now - lastStat).count() >= STATUS_INTERVAL_SEC) {
                        static std::mutex statsMutex;
                        std::lock_guard<std::mutex> lock(statsMutex);
                        
                        globalChecked += localChecked;
                        localChecked = 0ULL;
                        globalElapsed = std::chrono::duration<double>(now - tStart).count();
                        kps = globalChecked.load() / globalElapsed;

                        printStats(numCPUs, targetHash160, kps, globalChecked.load(),
                                   globalElapsed, g_candidatesFound.load(), g_matchesFound.load());
                        lastStat = now;
                    }
                }
            }

            globalChecked += localChecked;
        });
    }

    // Wait for all threads to complete
    for (auto& t : threads) {
        t.join();
    }

    if (!g_matchFound.load()) {
        system("clear");
        std::cout << "╔══════════════════════════════════════════════════════╗\n"
                  << "║                  SEARCH COMPLETED                   ║\n"
                  << "╠══════════════════════════════════════════════════════╣\n"
                  << "║ No exact match found.                                ║\n"
                  << "║ Total keys checked: " << std::setw(15) << formatLargeNumber(globalChecked.load()) << "                 ║\n"
                  << "║ Candidates found  : " << std::setw(15) << formatLargeNumber(g_candidatesFound.load()) << "                 ║\n"
                  << "║ Search time       : " << std::setw(15) << formatElapsedTime(globalElapsed) << "                 ║\n"
                  << "╚══════════════════════════════════════════════════════╝\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 0;
    }

    // Write found key to file
    writeFoundKey(g_foundPrivKey, targetHash160);

    system("clear");
    std::cout << "╔══════════════════════════════════════════════════════╗\n"
              << "║                   MATCH FOUND!                      ║\n"
              << "╠══════════════════════════════════════════════════════╣\n"
              << "║ Private Key: " << g_foundPrivKey << " ║\n"
              << "║ Public Key : " << g_foundPubKey << " ║\n"
              << "║ Hash160    : " << targetHash160 << " ║\n"
              << "║                                                      ║\n"
              << "║ Key saved to found.txt                               ║\n"
              << "╚══════════════════════════════════════════════════════╝\n";
    
    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}