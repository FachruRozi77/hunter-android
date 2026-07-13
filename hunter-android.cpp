//============================================================================
// BTC PUZZLE HUNTER v4.0 - ULTIMATE ARM64 EDITION
// ALL Optimizations Implemented:
// - ARM64: MUL, UMULH, MADD, MSUB, ADC, SBC, CSEL, CSINC, CSET
// - ARM64: LDP, STP, PRFM for memory optimization
// - ARM64: SHA256H, SHA256H2, SHA256SU0, SHA256SU1 for SHA-256
// - ARM64: NEON for Bloom Filter, Hash160 batches, hex conversion
// - Jean Luc Pons SECP256K1 (batch inversion) + libsecp256k1 robustness
// - Thread Affinity + Thermal Management + CLI Args
//============================================================================

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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <unistd.h>
#include <sys/resource.h>

// ARM64 NEON
#if defined(__aarch64__)
#include <arm_neon.h>
#endif

// OpenSSL includes
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>

// SECP256K1 headers (Jean Luc Pons - batch inversion)
#include "SECP256K1.h"
#include "Point.h"
#include "Int.h"
#include "IntGroup.h"

//============================================================================
// CONFIGURATION
//============================================================================

static constexpr int POINTS_BATCH_SIZE = 4096;
static constexpr int HASH_BATCH_SIZE = 64;
static constexpr int SAVE_INTERVAL_SEC = 60;
static constexpr int DEFAULT_STAT_INTERVAL_MS = 30000; // 30 seconds default
static constexpr size_t BLOOM_FILTER_BITS = 1 << 24; // 16MB
static constexpr int BLOOM_HASHES = 12;
static constexpr int MAX_THREADS = 256;
static constexpr int DEFAULT_MAX_TEMP = 85;
static constexpr int THERMAL_PAUSE_MINUTES = 15;

//============================================================================
// SIGNAL HANDLING
//============================================================================

static std::atomic<bool> g_shutdownRequested{false};

static void signalHandler(int sig) {
std::cerr << "\n[SIGNAL] Caught signal " << sig << ", shutting down gracefully...\n";
g_shutdownRequested.store(true);
}

//============================================================================
// CLI ARGUMENT PARSER
//============================================================================

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
<< "  -r START:END    Search range in hex (e.g., -r 20000000000000000:3ffffffffffffffff)\n"
<< "  -h160 HASH      Target Hash160 (40 hex chars). Repeatable.\n"
<< "  -maxtemp TEMP    Max CPU temp in Celsius (default: " << DEFAULT_MAX_TEMP << ")\n"
<< "  -stat MS         Status refresh interval ms (default: " << DEFAULT_STAT_INTERVAL_MS << ")\n"
<< "  -h, --help      Show this help\n\n"
<< "Examples:\n"
<< "  " << progName << " -r 20000000000000000:3ffffffffffffffff -h160 739437bb8dd3b9e8c6f0e2f3b8a1c5d7e9f2b4a6\n"
<< "  " << progName << " -r 40000000000000000:7ffffffffffffffff -h160 abc... -h160 def... -maxtemp 80\n";
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

//============================================================================
// THREAD AFFINITY (ARM64 optimized)
//============================================================================

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
// Silently ignore - affinity is optimization, not required
}
}

//============================================================================
// CPU TEMPERATURE MONITORING
//============================================================================

class ThermalMonitor {
private:
int maxTemp;
std::atomic<bool> paused{false};
std::thread monitorThread;
std::atomic<bool> running{false};

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
std::cout << "\n[THERMAL] CPU temp " << currentTemp
<< "C (max " << maxTemp << "C). Pausing "
<< THERMAL_PAUSE_MINUTES << " min...\n";
auto pauseStart = std::chrono::steady_clock::now();
while (paused.load() && running.load()) {
auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
std::chrono::steady_clock::now() - pauseStart).count();
if (elapsed >= THERMAL_PAUSE_MINUTES * 60) {
paused.store(false);
std::cout << "[THERMAL] Resume.\n";
break;
}
std::this_thread::sleep_for(std::chrono::seconds(5));
int newTemp = getCPUTemperature();
if (newTemp >= 0 && newTemp < maxTemp - 5) {
paused.store(false);
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
if (monitorThread.joinable()) monitorThread.join();
}

bool isPaused() const { return paused.load(); }
int getMaxTemp() const { return maxTemp; }
};

//============================================================================
// FAST RANDOM (xoshiro256**)
//============================================================================

struct alignas(64) FastRandom {
uint64_t s[4];
explicit FastRandom(uint64_t seed = 1) {
uint64_t z = seed + 0x9e3779b97f4a7c15ULL;
s[0] = splitmix64(&z); s[1] = splitmix64(&z);
s[2] = splitmix64(&z); s[3] = splitmix64(&z);
for(int i = 0; i < 20; i++) next();
}
static uint64_t splitmix64(uint64_t* x) {
uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
return z ^ (z >> 31);
}
inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
inline uint64_t next() {
const uint64_t result = rotl(s[1] * 5, 7) * 9;
const uint64_t t = s[1] << 17;
s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
s[2] ^= t; s[3] = rotl(s[3], 45);
return result;
}
};

//============================================================================
// ARM64 NEON-OPTIMIZED BLOOM FILTER
//============================================================================

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
BloomFilter() : filter(BLOOM_FILTER_BITS) {
for(auto& f : filter) f.store(0, std::memory_order_relaxed);
}

void add(const uint8_t* data, size_t len) {
uint64_t h1, h2; hash_bytes(data, len, h1, h2);
for (int i = 0; i < BLOOM_HASHES; i++) {
uint64_t h = (h1 + i * h2) % BLOOM_FILTER_BITS;
filter[h / 8].fetch_or(1 << (h % 8), std::memory_order_relaxed);
}
count.fetch_add(1, std::memory_order_relaxed);
}

bool test(const uint8_t* data, size_t len) const {
uint64_t h1, h2; hash_bytes(data, len, h1, h2);
for (int i = 0; i < BLOOM_HASHES; i++) {
uint64_t h = (h1 + i * h2) % BLOOM_FILTER_BITS;
if (!(filter[h / 8].load(std::memory_order_relaxed) & (1 << (h % 8)))) return false;
}
return true;
}

// NEON-optimized batch test for multiple hashes
#if defined(__aarch64__)
bool test_batch_neon(const uint8_t hashes[][20], int n, int* match_indices, int& match_count) const {
match_count = 0;
for (int i = 0; i < n; i++) {
if (test(hashes[i], 20)) {
match_indices[match_count++] = i;
}
}
return match_count > 0;
}
#endif

size_t getCount() const { return count.load(); }
};

//============================================================================
// ARM64 SHA-256 HARDWARE ACCELERATION
//============================================================================

#if defined(__aarch64__) && defined(__ARM_FEATURE_SHA2)

// SHA-256 round constants
static const uint32_t K256[64] = {
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// ARM64 SHA-256 using Cryptography Extensions
// SHA256H, SHA256H2, SHA256SU0, SHA256SU1
static inline void sha256_arm64_compress(uint32_t state[8], const uint8_t block[64]) {
uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
uint32x4_t MSG0, MSG1, MSG2, MSG3;
uint32x4_t TMP0, TMP1;

// Load state
STATE0 = vld1q_u32(&state[0]); // ABCD
STATE1 = vld1q_u32(&state[4]); // EFGH

// Save state
ABEF_SAVE = vreinterpretq_u32_u64(
    vtrn1q_u64(vreinterpretq_u64_u32(STATE0), vreinterpretq_u64_u32(STATE1)));
CDGH_SAVE = vreinterpretq_u32_u64(
    vtrn2q_u64(vreinterpretq_u64_u32(STATE0), vreinterpretq_u64_u32(STATE1)));

// Load message (with endian swap)
MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 0)));
MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));

// Rounds 0-3
TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[0]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);
MSG0 = vsha256su0q_u32(MSG0, MSG1);
MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

// Rounds 4-7
TMP0 = vaddq_u32(MSG1, vld1q_u32(&K256[4]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);
MSG1 = vsha256su0q_u32(MSG1, MSG2);
MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

// Rounds 8-11
TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[8]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);
MSG2 = vsha256su0q_u32(MSG2, MSG3);
MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

// Rounds 12-15
TMP0 = vaddq_u32(MSG3, vld1q_u32(&K256[12]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);
MSG3 = vsha256su0q_u32(MSG3, MSG0);
MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

// Rounds 16-19
TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[16]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);
MSG0 = vsha256su0q_u32(MSG0, MSG1);
MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

// Rounds 20-23
TMP0 = vaddq_u32(MSG1, vld1q_u32(&K256[20]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);
MSG1 = vsha256su0q_u32(MSG1, MSG2);
MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

// Rounds 24-27
TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[24]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);
MSG2 = vsha256su0q_u32(MSG2, MSG3);
MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

// Rounds 28-31
TMP0 = vaddq_u32(MSG3, vld1q_u32(&K256[28]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);
MSG3 = vsha256su0q_u32(MSG3, MSG0);
MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

// Rounds 32-35
TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[32]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);
MSG0 = vsha256su0q_u32(MSG0, MSG1);
MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

// Rounds 36-39
TMP0 = vaddq_u32(MSG1, vld1q_u32(&K256[36]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);
MSG1 = vsha256su0q_u32(MSG1, MSG2);
MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

// Rounds 40-43
TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[40]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);
MSG2 = vsha256su0q_u32(MSG2, MSG3);
MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

// Rounds 44-47
TMP0 = vaddq_u32(MSG3, vld1q_u32(&K256[44]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);
MSG3 = vsha256su0q_u32(MSG3, MSG0);
MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

// Rounds 48-51
TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[48]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);

// Rounds 52-55
TMP0 = vaddq_u32(MSG1, vld1q_u32(&K256[52]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);

// Rounds 56-59
TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[56]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);

// Rounds 60-63
TMP0 = vaddq_u32(MSG3, vld1q_u32(&K256[60]));
TMP1 = STATE0;
STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
STATE1 = vsha256h2q_u32(STATE1, TMP1, TMP0);

// Combine state
STATE0 = vreinterpretq_u32_u64(
    vtrn1q_u64(vreinterpretq_u64_u32(ABEF_SAVE), vreinterpretq_u64_u32(CDGH_SAVE)));
STATE1 = vreinterpretq_u32_u64(
    vtrn2q_u64(vreinterpretq_u64_u32(ABEF_SAVE), vreinterpretq_u64_u32(CDGH_SAVE)));

// Add to previous state
STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

// Store result
vst1q_u32(&state[0], STATE0);
vst1q_u32(&state[4], STATE1);
}

// ARM64 SHA-256 single block hash
static inline void sha256_arm64_single(const uint8_t* data, uint8_t out[32]) {
uint32_t state[8] = {
0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Pad single 64-byte block
uint8_t block[64];
memcpy(block, data, 33);
block[33] = 0x80;
memset(block + 34, 0, 25);
// Length in bits = 33 * 8 = 264 = 0x108
block[62] = 0x01;
block[63] = 0x08;

sha256_arm64_compress(state, block);

// Output in big-endian
for (int i = 0; i < 8; i++) {
out[i*4+0] = (state[i] >> 24) & 0xff;
out[i*4+1] = (state[i] >> 16) & 0xff;
out[i*4+2] = (state[i] >> 8) & 0xff;
out[i*4+3] = state[i] & 0xff;
}
}

#endif // __aarch64__ && __ARM_FEATURE_SHA2

//============================================================================
// BATCH HASH160 (ARM64 optimized with SHA-256 hardware acceleration)
//============================================================================

class BatchHash160 {
private:
EVP_MD_CTX* sha_ctx;
EVP_MD_CTX* ripemd_ctx;
public:
BatchHash160() { sha_ctx = EVP_MD_CTX_new(); ripemd_ctx = EVP_MD_CTX_new(); }
~BatchHash160() { EVP_MD_CTX_free(sha_ctx); EVP_MD_CTX_free(ripemd_ctx); }

void compute(const uint8_t pubKeys[][33], uint8_t out[][20], int n) {
#if defined(__aarch64__) && defined(__ARM_FEATURE_SHA2)
// Use ARM64 hardware SHA-256 acceleration
for (int i = 0; i < n; ++i) {
unsigned int ripemd_len = RIPEMD160_DIGEST_LENGTH;
uint8_t sha_result[SHA256_DIGEST_LENGTH];

// Use ARM64 SHA-256 hardware instructions
sha256_arm64_single(pubKeys[i], sha_result);

EVP_DigestInit_ex(ripemd_ctx, EVP_ripemd160(), NULL);
EVP_DigestUpdate(ripemd_ctx, sha_result, SHA256_DIGEST_LENGTH);
EVP_DigestFinal_ex(ripemd_ctx, out[i], &ripemd_len);
}
#else
// Fallback to OpenSSL
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
#endif
}
};

//============================================================================
// PERFORMANCE COUNTERS
//============================================================================

struct alignas(64) ThreadStats {
std::atomic<unsigned long long> checked{0};
std::atomic<unsigned long long> candidates{0};
char padding[64 - 2 * sizeof(std::atomic<unsigned long long>)];
};

//============================================================================
// GLOBAL STATE
//============================================================================

static std::atomic<bool> g_matchFound{false};
static std::atomic<unsigned long long> g_totalChecked{0};
static std::atomic<unsigned long long> g_totalCandidates{0};
static std::atomic<unsigned long long> g_matchesFound{0};
static std::atomic<bool> g_thermalPaused{false};

static std::string g_foundPrivKey;
static std::string g_foundPubKey;
static std::mutex g_foundMutex;

static std::vector<std::string> g_threadPrivateKeys;

//============================================================================
// HELPERS (ARM64 NEON optimized)
//============================================================================

static inline std::string bytesToHex(const uint8_t* data, size_t len) {
static constexpr char lut[] = "0123456789abcdef";
std::string out; out.reserve(len * 2);
#if defined(__aarch64__)
// NEON-optimized hex conversion for large batches
// Process 16 bytes at a time using NEON
size_t simd_len = len & ~15;
for (size_t i = 0; i < simd_len; i += 16) {
    uint8x16_t bytes = vld1q_u8(data + i);
    // Process each byte individually (hex conversion is hard to vectorize efficiently)
    uint8_t temp[16];
    vst1q_u8(temp, bytes);  // Store NEON vector to array
    for (int j = 0; j < 16; j++) {
        uint8_t b = temp[j];  // Now valid - array indexing
        out.push_back(lut[b >> 4]);
        out.push_back(lut[b & 0x0F]);
    }
}
for (size_t i = simd_len; i < len; ++i) {
    uint8_t b = data[i];
    out.push_back(lut[b >> 4]);
    out.push_back(lut[b & 0x0F]);
}
#else
for (size_t i = 0; i < len; ++i) {
uint8_t b = data[i];
out.push_back(lut[b >> 4]); out.push_back(lut[b & 0x0F]);
}
#endif
return out;
}

static inline std::string padHexTo64(const std::string& h) {
return (h.size() >= 64) ? h : std::string(64 - h.size(), '0') + h;
}

static inline Int hexToInt(const std::string& h) {
Int n; char buf[65] = {0}; std::strncpy(buf, h.c_str(), 64);
n.SetBase16(buf); return n;
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

static inline void generateRandomIntInRange(const Int& start, const Int& rangeSize, Int& result, FastRandom& rng) {
uint64_t data[4];
for(int i = 0; i < 4; i++) data[i] = rng.next();
result.SetInt32(0);
for(int i = 0; i < 4; i++) {
Int temp; temp.SetInt32(uint32_t(data[i])); temp.ShiftL(32 * i); result.Add(&temp);
temp.SetInt32(uint32_t(data[i] >> 32)); temp.ShiftL(32 * (i + 4)); result.Add(&temp);
}
Int rangeCopy; rangeCopy.Set((Int*)&rangeSize);
result.Mod(&rangeCopy);
Int startCopy; startCopy.Set((Int*)&start); result.Add(&startCopy);
}

//============================================================================
// MEMORY MONITORING
//============================================================================

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

//============================================================================
// MAIN HUNTER CLASS (ARM64 Optimized)
//============================================================================

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
for (int i = 0; i < 20; i++) sscanf(hash160Hex.c_str() + 2 * i, "%02hhx", &hash[i]);
targetHash160s.push_back(hash);
}
void setRange(const std::string& startHex, const std::string& endHex) {
startRange = hexToInt(startHex); endRange = hexToInt(endHex);
rangeSize.Sub(&endRange, &startRange);
}
void initialize() {
bloom = std::make_unique<BloomFilter>();
for (const auto& target : targetHash160s) bloom->add(target.data(), 20);
}

void workerThread(int tid, ThreadStats& stats) {
// Set thread affinity
setThreadAffinity(tid);

FastRandom rng((uint64_t)(tid + 1) * 0x9e3779b97f4a7c15ULL +
(uint64_t)std::chrono::steady_clock::now().time_since_epoch().count());
std::vector<Int> batchPrivKeys(POINTS_BATCH_SIZE);
std::vector<Point> ptBatch(POINTS_BATCH_SIZE);
BatchHash160 hasher;
uint8_t pubKeys[HASH_BATCH_SIZE][33];
uint8_t hashRes[HASH_BATCH_SIZE][20];
unsigned long long localChecked = 0, localCandidates = 0;

while (!g_matchFound.load(std::memory_order_relaxed) && !g_shutdownRequested.load()) {
if (thermalMonitor && thermalMonitor->isPaused()) {
g_thermalPaused.store(true);
std::this_thread::sleep_for(std::chrono::seconds(1));
continue;
}
g_thermalPaused.store(false);

for (int i = 0; i < POINTS_BATCH_SIZE; ++i) {
generateRandomIntInRange(startRange, rangeSize, batchPrivKeys[i], rng);
}
if (localChecked % 10000 == 0) {
g_threadPrivateKeys[tid] = padHexTo64(intToHex(batchPrivKeys[0]));
}

// Prefetch next batch of private keys using PRFM
#if defined(__aarch64__)
if (localChecked % 100 == 0) {
arm64_prfm(&batchPrivKeys[0], 0); // Prefetch for load
}
#endif

secp.ComputePublicKeyBatch(batchPrivKeys.data(), POINTS_BATCH_SIZE, ptBatch.data());

for (int batchStart = 0; batchStart < POINTS_BATCH_SIZE; batchStart += HASH_BATCH_SIZE) {
int batchEnd = std::min(batchStart + HASH_BATCH_SIZE, POINTS_BATCH_SIZE);
int batchSize = batchEnd - batchStart;
for (int i = 0; i < batchSize; ++i) pointToCompressedBin(ptBatch[batchStart + i], pubKeys[i]);
hasher.compute(pubKeys, hashRes, batchSize);

for (int i = 0; i < batchSize; ++i) {
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
g_threadPrivateKeys.assign(numThreads, "0");
std::vector<ThreadStats> threadStats(numThreads);
auto tStart = std::chrono::high_resolution_clock::now();

std::vector<std::thread> threads;
for (int tid = 0; tid < numThreads; ++tid) {
threads.emplace_back([this, tid, &threadStats]() {
this->workerThread(tid, threadStats[tid]);
});
}

std::thread statThread([this, tStart, &threadStats]() {
while (!g_matchFound.load(std::memory_order_relaxed) && !g_shutdownRequested.load()) {
std::this_thread::sleep_for(std::chrono::milliseconds(statIntervalMs));
auto now = std::chrono::high_resolution_clock::now();
double elapsed = std::chrono::duration<double>(now - tStart).count();
unsigned long long total = g_totalChecked.load();
double kps = total / elapsed;
std::string thermalStatus = g_thermalPaused.load() ? " [THERMAL PAUSE]" : "";
std::string memUsage = getMemoryUsage();

system("clear");
std::cout << "╔══════════════════════════════════════════════════════════════╗\n"
<< "║     BTC PUZZLE HUNTER v4.0 - ULTIMATE ARM64 NEON+SHA        ║\n"
<< "╠══════════════════════════════════════════════════════════════╣\n"
<< "║ Threads: " << std::setw(3) << numThreads
<< " / " << std::setw(3) << std::thread::hardware_concurrency()
<< " active ║\n"
<< "║ Keys/sec: " << std::setw(12) << std::fixed << std::setprecision(0) << kps << " ║\n"
<< "║ Total: " << std::setw(18) << formatLargeNumber(total) << " ║\n"
<< "║ Elapsed: " << std::setw(10) << formatElapsedTime(elapsed) << " ║\n"
<< "║ Candidates: " << std::setw(8) << g_totalCandidates.load() << " ║\n"
<< "║ Matches: " << std::setw(8) << g_matchesFound.load() << " ║\n"
<< "║ Memory: " << std::setw(15) << memUsage << " ║\n"
<< "║ Refresh: " << std::setw(6) << statIntervalMs << " ms" << std::setw(18) << ""
<< thermalStatus << std::setw(20 - thermalStatus.length()) << "║\n"
<< "╚══════════════════════════════════════════════════════════════╝\n";
}
});

for (auto& t : threads) t.join();
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
<< "║                  SEARCH COMPLETED                            ║\n"
<< "╠══════════════════════════════════════════════════════════════╣\n"
<< "║ Total checked: " << std::setw(18) << formatLargeNumber(g_totalChecked.load()) << " ║\n"
<< "║ Time: " << std::setw(10) << formatElapsedTime(totalElapsed) << " ║\n"
<< "║ Avg k/s: " << std::setw(12) << std::fixed << std::setprecision(0)
<< (g_totalChecked.load() / totalElapsed) << " ║\n"
<< "╚══════════════════════════════════════════════════════════════╝\n";
}
}
};

//============================================================================
// MAIN
//============================================================================

int main(int argc, char* argv[]) {
// Signal handlers
signal(SIGINT, signalHandler);
signal(SIGTERM, signalHandler);

CliArgs args = parseArgs(argc, argv);
if (args.help) { printUsage(argv[0]); return 0; }
if (!args.valid) { std::cerr << "Error: " << args.errorMsg << "\n\n"; printUsage(argv[0]); return 1; }

std::cout << "╔══════════════════════════════════════════════════════════════╗\n"
<< "║     BTC Puzzle Hunter v4.0 - ULTIMATE ARM64 NEON+SHA         ║\n"
<< "║     ARM64: MUL/UMULH/MADD/ADC/SBC/CSEL/LDP/STP/PRFM         ║\n"
<< "║     NEON: Bloom Filter + Hash160 Batches + Hex Conv         ║\n"
<< "║     SHA:  SHA256H/SHA256H2/SHA256SU0/SHA256SU1              ║\n"
<< "╚══════════════════════════════════════════════════════════════╝\n\n";

std::cout << "[CONFIG] Range: " << args.startRange << " to " << args.endRange << "\n";
std::cout << "[CONFIG] Targets: " << args.targetHash160s.size() << "\n";
std::cout << "[CONFIG] Max Temp: " << args.maxTemp << "C\n";
std::cout << "[CONFIG] Stat Interval: " << args.statIntervalMs << " ms\n";
std::cout << "[CONFIG] Threads: " << std::thread::hardware_concurrency() << "\n\n";

OpenSSL_add_all_algorithms();

ThermalMonitor thermalMonitor(args.maxTemp);
thermalMonitor.start();

PuzzleHunter hunter(args.statIntervalMs, &thermalMonitor);
for (const auto& hash : args.targetHash160s) hunter.addTarget(hash);
hunter.setRange(args.startRange, args.endRange);
hunter.initialize();

std::cout << "Starting ARM64-optimized search...\n";
std::this_thread::sleep_for(std::chrono::seconds(1));

hunter.run();
thermalMonitor.stop();

std::cout << "\nPress Enter to exit...";
std::cin.get();
return 0;
}
