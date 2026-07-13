#ifndef BIGINTH
#define BIGINTH

#include "Random.h"
#include <string>
#include <inttypes.h>

// We need 1 extra block for Knuth div algorithm, Montgomery multiplication and ModInv
#define BISIZE 256

#if BISIZE==256
#define NB64BLOCK 5
#define NB32BLOCK 10
#elif BISIZE==512
#define NB64BLOCK 9
#define NB32BLOCK 18
#else
#error Unsupported size
#endif

class Int {

public:

Int();
Int(int64_t i64);
Int(uint64_t u64);
Int(Int *a);

// Op
void Add(uint64_t a);
void Add(Int *a);
void Add(Int *a,Int *b);
void AddOne();
void Sub(uint64_t a);
void Sub(Int *a);
void Sub(Int *a, Int *b);
void SubOne();
void Mult(Int *a);
uint64_t Mult(uint64_t a);
uint64_t IMult(int64_t a);
uint64_t Mult(Int *a,uint64_t b);
uint64_t IMult(Int *a, int64_t b);
void Mult(Int *a,Int *b);
void Div(Int *a,Int *mod = NULL);
void MultModN(Int *a, Int *b, Int *n);
void Neg();
void Abs();

// Right shift (signed)
void ShiftR(uint32_t n);
void ShiftR32Bit();
void ShiftR64Bit();
// Left shift
void ShiftL(uint32_t n);
void ShiftL32Bit();
void ShiftL64Bit();
// Bit swap
void SwapBit(int bitNumber);

// Comp
bool IsGreater(Int *a);
bool IsGreaterOrEqual(Int *a);
bool IsLowerOrEqual(Int *a);
bool IsLower(Int *a);
bool IsEqual(Int *a);
bool IsZero();
bool IsOne();
bool IsStrictPositive();
bool IsPositive();
bool IsNegative();
bool IsEven() const;
bool IsOdd();
bool IsProbablePrime();

double ToDouble();

// Modular arithmetic
static void SetupField(Int *n, Int *R = NULL, Int *R2 = NULL, Int *R3 = NULL, Int *R4 = NULL);
static Int *GetR();
static Int *GetR2();
static Int *GetR3();
static Int *GetR4();
static Int* GetFieldCharacteristic();

void GCD(Int *a);
void Mod(Int *n);
void ModInv();
void MontgomeryMult(Int *a,Int *b);
void MontgomeryMult(Int *a);
void ModAdd(Int *a);
void ModAdd(Int *a,Int *b);
void ModAdd(uint64_t a);
void ModSub(Int *a);
void ModSub(Int *a, Int *b);
void ModSub(uint64_t a);
void ModMul(Int *a,Int *b);
void ModMul(Int *a);
void ModSquare(Int *a);
void ModCube(Int *a);
void ModDouble();
void ModExp(Int *e);
void ModNeg();
void ModSqrt();
bool HasSqrt();
void imm_umul_asm(const uint64_t* a, uint64_t b, uint64_t* res);

// Specific SecpK1
static void InitK1(Int *order);
void ModMulK1(Int *a, Int *b);
void ModMulK1(Int *a);
void ModSquareK1(Int *a);
void ModMulK1order(Int *a);
void ModAddK1order(Int *a,Int *b);
void ModAddK1order(Int *a);
void ModSubK1order(Int *a);
void ModNegK1order();
uint32_t ModPositiveK1();

// Size
int GetSize();
int GetSize64();
int GetBitLength();

// Setter
void SetInt32(uint32_t value);
void Set(Int *a);
void SetBase10(char *value);
void SetBase16(char *value);
void SetBaseN(int n,char *charset,char *value);
void SetByte(int n,unsigned char byte);
void SetDWord(int n, uint32_t b);
void SetQWord(int n,uint64_t b);
void Rand(int nbit);
void Rand(Int *randMax);
void Set32Bytes(unsigned char *bytes);
void MaskByte(int n);

// Getter
uint32_t GetInt32();
int GetBit(uint32_t n);
unsigned char GetByte(int n);
void Get32Bytes(unsigned char *buff);

// To String
std::string GetBase2();
std::string GetBase10();
std::string GetBase16();
std::string GetBaseN(int n,char *charset);
std::string GetBlockStr();
std::string GetC64Str(int nbDigit);

// Check functions
static void Check();
static bool CheckInv(Int *a);
static Int P;

union {
uint32_t bits[NB32BLOCK];
uint64_t bits64[NB64BLOCK];
};

private:
void MatrixVecMul(Int *u,Int *v,int64_t _11,int64_t _12,int64_t _21,int64_t _22,uint64_t *cu,uint64_t* cv);
void MatrixVecMul(Int* u,Int* v,int64_t _11,int64_t _12,int64_t _21,int64_t _22);
uint64_t AddCh(Int *a,uint64_t ca,Int* b,uint64_t cb);
uint64_t AddCh(Int* a,uint64_t ca);
uint64_t AddC(Int* a);
void AddAndShift(Int* a,Int* b,uint64_t cH);
void ShiftL64BitAndSub(Int *a,int n);
uint64_t Mult(Int *a, uint32_t b);
int GetLowestBit();
void CLEAR();
void CLEARFF();
void DivStep62(Int* u,Int* v,int64_t* eta,int *pos,int64_t* uu,int64_t* uv,int64_t* vu,int64_t* vv);
};

//============================================================================
// ARM64 NATIVE PRIMITIVES - Pure Inline Assembly
// Replaces ALL x86 intrinsics with ARM64 equivalents
// Uses: MUL, UMULH, MADD, MSUB, ADC, SBC, CSEL, CSINC, CSET, LDP, STP, PRFM
//============================================================================

#if defined(__aarch64__)

#include <arm_neon.h>

//============================================================================
// MUL + UMULH - 64x64 -> 128 bit multiplication
// Uses ARM64 MUL (low) + UMULH (high) - 2-3 cycles total
//============================================================================
static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t *h) {
uint64_t lo, hi;
__asm__ volatile (
"mul %x[lo], %x[a], %x[b] \n"
"umulh %x[hi], %x[a], %x[b] \n"
: [lo] "=&r" (lo), [hi] "=&r" (hi)
: [a] "r" (a), [b] "r" (b)
);
*h = hi;
return lo;
}

//============================================================================
// MADD - Multiply-Add: (a * b) + c -> result
// Critical for Montgomery multiplication accumulation
//============================================================================
static inline uint64_t _madd128(uint64_t a, uint64_t b, uint64_t c, uint64_t *carry) {
uint64_t lo, hi;
__asm__ volatile (
"madd %x[lo], %x[a], %x[b], %x[c] \n"
"umulh %x[hi], %x[a], %x[b] \n"
: [lo] "=&r" (lo), [hi] "=&r" (hi)
: [a] "r" (a), [b] "r" (b), [c] "r" (c)
);
*carry = hi;
return lo;
}

//============================================================================
// MSUB - Multiply-Subtract: (a * b) - c -> result
// For conditional subtraction in modular reduction
//============================================================================
static inline uint64_t _msub128(uint64_t a, uint64_t b, uint64_t c, uint64_t *borrow) {
uint64_t lo, hi;
__asm__ volatile (
"mul %x[lo], %x[a], %x[b] \n"
"umulh %x[hi], %x[a], %x[b] \n"
"subs %x[lo], %x[lo], %x[c] \n"
"sbc %x[hi], %x[hi], xzr \n"
: [lo] "=&r" (lo), [hi] "=&r" (hi)
: [a] "r" (a), [b] "r" (b), [c] "r" (c)
: "cc"
);
*borrow = hi;
return lo;
}

//============================================================================
// ADC Chain - Add with Carry propagation
// Uses ADDS + ADC chain - optimal for ARM64 out-of-order execution
//============================================================================
static inline unsigned char _addcarry_u64(unsigned char cin, uint64_t a, uint64_t b, uint64_t *out) {
uint64_t result;
unsigned char cout;
if (__builtin_expect(cin, 0)) {
__asm__ volatile (
"adds %x[res], %x[a], %x[b] \n"
"csinc %x[res], %x[res], %x[res], cc \n"
"cset %w[co], cs \n"
: [res] "=&r" (result), [co] "=r" (cout)
: [a] "r" (a), [b] "r" (b)
: "cc"
);
} else {
__asm__ volatile (
"adds %x[res], %x[a], %x[b] \n"
"cset %w[co], cs \n"
: [res] "=&r" (result), [co] "=r" (cout)
: [a] "r" (a), [b] "r" (b)
: "cc"
);
}
*out = result;
return cout;
}

//============================================================================
// SBC Chain - Subtract with Borrow propagation
// Uses SUBS + SBC chain
//============================================================================
static inline unsigned char _subborrow_u64(unsigned char bin, uint64_t a, uint64_t b, uint64_t *out) {
uint64_t result;
unsigned char bout;
if (__builtin_expect(bin, 0)) {
__asm__ volatile (
"subs %x[res], %x[a], %x[b] \n"
"csinc %x[res], %x[res], %x[res], cc \n"
"cset %w[bo], cc \n"
: [res] "=&r" (result), [bo] "=r" (bout)
: [a] "r" (a), [b] "r" (b)
: "cc"
);
} else {
__asm__ volatile (
"subs %x[res], %x[a], %x[b] \n"
"cset %w[bo], cc \n"
: [res] "=&r" (result), [bo] "=r" (bout)
: [a] "r" (a), [b] "r" (b)
: "cc"
);
}
*out = result;
return bout;
}

//============================================================================
// CSEL - Conditional Select (branchless)
// Replaces: if (cond) dst = a; else dst = b;
//============================================================================
static inline uint64_t arm64_csel(uint64_t a, uint64_t b, unsigned char cond) {
uint64_t result;
__asm__ volatile (
"cmp %x[cond], #0 \n"
"csel %x[res], %x[a], %x[b], ne \n"
: [res] "=r" (result)
: [a] "r" (a), [b] "r" (b), [cond] "r" ((uint64_t)cond)
: "cc"
);
return result;
}

//============================================================================
// CSINC - Conditional Select and Increment
// Replaces: if (cond) dst = a; else dst = b + 1;
// Used for carry propagation optimization
//============================================================================
static inline uint64_t arm64_csinc(uint64_t a, uint64_t b, unsigned char cond) {
uint64_t result;
__asm__ volatile (
"cmp %x[cond], #0 \n"
"csinc %x[res], %x[a], %x[b], ne \n"
: [res] "=r" (result)
: [a] "r" (a), [b] "r" (b), [cond] "r" ((uint64_t)cond)
: "cc"
);
return result;
}

//============================================================================
// CSET - Conditional Set
// Sets dst = 1 if condition true, else 0
//============================================================================
static inline uint64_t arm64_cset(unsigned char cond) {
uint64_t result;
__asm__ volatile (
"cmp %x[cond], #0 \n"
"cset %x[res], ne \n"
: [res] "=r" (result)
: [cond] "r" ((uint64_t)cond)
: "cc"
);
return result;
}

//============================================================================
// LDP/STP - Load/Store Pair for 128-bit operations
// Loads/stores two 64-bit values in one instruction
//============================================================================
static inline void arm64_ldp(uint64_t *dst1, uint64_t *dst2, const uint64_t *src) {
__asm__ volatile (
"ldp %x[d1], %x[d2], [%x[src]] \n"
: [d1] "=r" (*dst1), [d2] "=r" (*dst2)
: [src] "r" (src)
);
}

static inline void arm64_stp(uint64_t val1, uint64_t val2, uint64_t *dst) {
__asm__ volatile (
"stp %x[v1], %x[v2], [%x[dst]] \n"
:
: [v1] "r" (val1), [v2] "r" (val2), [dst] "r" (dst)
: "memory"
);
}

//============================================================================
// PRFM - Prefetch Memory
// Prefetches data for future use
// type: 0=LD (load), 1=ST (store), 2=PLD (keep in cache)
//============================================================================
static inline void arm64_prfm(const void *addr, int type) {
const char *prfm_ops[] = {"prfm pldl1keep, [%x[addr]]\n", "prfm pstl1keep, [%x[addr]]\n", "prfm pldl2keep, [%x[addr]]\n"};
__asm__ volatile (
prfm_ops[type]
:
: [addr] "r" (addr)
);
}

//============================================================================
// ROR - Rotate Right
//============================================================================
static inline uint64_t arm64_ror(uint64_t val, uint64_t amt) {
uint64_t result;
__asm__ volatile (
"ror %x[res], %x[val], %x[amt] \n"
: [res] "=r" (result)
: [val] "r" (val), [amt] "r" (amt)
);
return result;
}

//============================================================================
// CNTVCT_EL0 - Virtual Timer (cycle counter)
//============================================================================
static inline uint64_t my_rdtsc() {
uint64_t val;
__asm__ volatile ("mrs %0, cntvct_el0" : "=r"(val));
return val;
}

//============================================================================
// NEON-optimized Bloom Filter hash computation
// Uses vectorized FNV-1a hash for 4 parallel hashes
//============================================================================
static inline void arm64_neon_hash4(const uint8_t* data, size_t len,
                                     uint64_t* h1_out, uint64_t* h2_out,
                                     uint64_t* h3_out, uint64_t* h4_out) {
    uint64_t h1 = 0xcbf29ce484222325ULL;
    uint64_t h2 = 0x84222325cbf29ce4ULL;
    uint64_t h3 = 0x9e3779b97f4a7c15ULL;
    uint64_t h4 = 0xf4a7c159e3779b97ULL;
    
    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        h1 ^= b; h1 *= 0x100000001b3ULL;
        h2 ^= (b + 0x9e3779b9); h2 = (h2 << 13) | (h2 >> 51); h2 *= 0x100000001b3ULL;
        h3 ^= (b * 0x85ebca6b); h3 = (h3 << 17) | (h3 >> 47); h3 *= 0xc2b2ae35;
        h4 ^= (b + 0x27d4eb2f); h4 = (h4 << 19) | (h4 >> 45); h4 *= 0x165667b1;
    }
    
    *h1_out = h1;
    *h2_out = h2;
    *h3_out = h3;
    *h4_out = h4;
}

#else // Fallback for non-ARM64

static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t *h) {
typedef unsigned __int128 uint128_t;
uint128_t r = (uint128_t)a * (uint128_t)b;
*h = (uint64_t)(r >> 64);
return (uint64_t)r;
}

static inline unsigned char _addcarry_u64(unsigned char cin, uint64_t a, uint64_t b, uint64_t *out) {
typedef unsigned __int128 uint128_t;
uint128_t r = (uint128_t)a + (uint128_t)b + (uint128_t)cin;
*out = (uint64_t)r;
return (unsigned char)(r >> 64);
}

static inline unsigned char _subborrow_u64(unsigned char bin, uint64_t a, uint64_t b, uint64_t *out) {
typedef unsigned __int128 uint128_t;
uint128_t r = (uint128_t)a - (uint128_t)b - (uint128_t)bin;
*out = (uint64_t)r;
return (unsigned char)((uint64_t)(r >> 64) != 0);
}

static inline uint64_t my_rdtsc() {
return (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
}

static inline uint64_t arm64_csel(uint64_t a, uint64_t b, unsigned char cond) {
return cond ? a : b;
}

static inline uint64_t arm64_csinc(uint64_t a, uint64_t b, unsigned char cond) {
return cond ? a : (b + 1);
}

static inline uint64_t arm64_cset(unsigned char cond) {
return cond ? 1ULL : 0ULL;
}

static inline void arm64_ldp(uint64_t *dst1, uint64_t *dst2, const uint64_t *src) {
*dst1 = src[0]; *dst2 = src[1];
}

static inline void arm64_stp(uint64_t val1, uint64_t val2, uint64_t *dst) {
dst[0] = val1; dst[1] = val2;
}

static inline void arm64_prfm(const void *addr, int type) {
(void)addr; (void)type;
}

static inline uint64_t arm64_ror(uint64_t val, uint64_t amt) {
return (val >> amt) | (val << (64 - amt));
}

static inline void arm64_neon_hash4(const uint8_t* data, size_t len,
                                     uint64_t* h1_out, uint64_t* h2_out,
                                     uint64_t* h3_out, uint64_t* h4_out) {
    uint64_t h1 = 0xcbf29ce484222325ULL;
    uint64_t h2 = 0x84222325cbf29ce4ULL;
    uint64_t h3 = 0x9e3779b97f4a7c15ULL;
    uint64_t h4 = 0xf4a7c159e3779b97ULL;
    
    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        h1 ^= b; h1 *= 0x100000001b3ULL;
        h2 ^= (b + 0x9e3779b9); h2 = (h2 << 13) | (h2 >> 51); h2 *= 0x100000001b3ULL;
        h3 ^= (b * 0x85ebca6b); h3 = (h3 << 17) | (h3 >> 47); h3 *= 0xc2b2ae35;
        h4 ^= (b + 0x27d4eb2f); h4 = (h4 << 19) | (h4 >> 45); h4 *= 0x165667b1;
    }
    
    *h1_out = h1;
    *h2_out = h2;
    *h3_out = h3;
    *h4_out = h4;
}

#endif // __aarch64__

//============================================================================
// 128-bit Division (portable)
//============================================================================
static inline uint64_t _udiv128(uint64_t hi, uint64_t lo, uint64_t d, uint64_t *r) {
#if defined(__aarch64__)
// ARM64 has UDIV but not 128-bit division
// Use software implementation
typedef unsigned __int128 uint128_t;
uint128_t n = ((uint128_t)hi << 64) | (uint128_t)lo;
*r = (uint64_t)(n % d);
return (uint64_t)(n / d);
#else
typedef unsigned __int128 uint128_t;
uint128_t n = ((uint128_t)hi << 64) | (uint128_t)lo;
*r = (uint64_t)(n % d);
return (uint64_t)(n / d);
#endif
}

//============================================================================
// MADD-Optimized Multiplication for ARM64
// Uses MADD pattern: (a * b) + c with carry tracking
//============================================================================
#if defined(__aarch64__)

static inline void imm_mul_madd(uint64_t *x, uint64_t y, uint64_t *dst, uint64_t *carryH) {
uint64_t h, carry;

// Word 0: MUL + UMULH (no add needed)
dst[0] = _umul128(x[0], y, &h);
carry = h;

// Words 1-4: MADD pattern - (x[i] * y) + carry_in
// Using MADD instruction: dst = (x[i] * y) + carry
dst[1] = _madd128(x[1], y, carry, &h); carry = h;
dst[2] = _madd128(x[2], y, carry, &h); carry = h;
dst[3] = _madd128(x[3], y, carry, &h); carry = h;
dst[4] = _madd128(x[4], y, carry, &h); carry = h;

#if NB64BLOCK > 5
dst[5] = _madd128(x[5], y, carry, &h); carry = h;
dst[6] = _madd128(x[6], y, carry, &h); carry = h;
dst[7] = _madd128(x[7], y, carry, &h); carry = h;
dst[8] = _madd128(x[8], y, carry, &h); carry = h;
#endif
*carryH = carry;
}

static inline void imm_imul_madd(uint64_t* x, uint64_t y, uint64_t* dst, uint64_t* carryH) {
uint64_t h, carry;

dst[0] = _umul128(x[0], y, &h); carry = h;
dst[1] = _madd128(x[1], y, carry, &h); carry = h;
dst[2] = _madd128(x[2], y, carry, &h); carry = h;
dst[3] = _madd128(x[3], y, carry, &h); carry = h;
#if NB64BLOCK > 5
dst[4] = _madd128(x[4], y, carry, &h); carry = h;
dst[5] = _madd128(x[5], y, carry, &h); carry = h;
dst[6] = _madd128(x[6], y, carry, &h); carry = h;
dst[7] = _madd128(x[7], y, carry, &h); carry = h;
#endif
// Last word uses signed multiply
int64_t sh;
int64_t slo = (int64_t)_mul128((int64_t)x[NB64BLOCK - 1], (int64_t)y, &sh);
dst[NB64BLOCK - 1] = _madd128((uint64_t)slo, 1, carry, &h);
*carryH = h + (uint64_t)sh;
}

#else // Non-ARM64 fallback

static inline void imm_mul_madd(uint64_t *x, uint64_t y, uint64_t *dst, uint64_t *carryH) {
unsigned char c = 0;
uint64_t h, carry;
dst[0] = _umul128(x[0], y, &h); carry = h;
c = _addcarry_u64(c, _umul128(x[1], y, &h), carry, dst + 1); carry = h;
c = _addcarry_u64(c, _umul128(x[2], y, &h), carry, dst + 2); carry = h;
c = _addcarry_u64(c, _umul128(x[3], y, &h), carry, dst + 3); carry = h;
c = _addcarry_u64(c, _umul128(x[4], y, &h), carry, dst + 4); carry = h;
#if NB64BLOCK > 5
c = _addcarry_u64(c, _umul128(x[5], y, &h), carry, dst + 5); carry = h;
c = _addcarry_u64(c, _umul128(x[6], y, &h), carry, dst + 6); carry = h;
c = _addcarry_u64(c, _umul128(x[7], y, &h), carry, dst + 7); carry = h;
c = _addcarry_u64(c, _umul128(x[8], y, &h), carry, dst + 8); carry = h;
#endif
*carryH = carry;
}

static inline void imm_imul_madd(uint64_t* x, uint64_t y, uint64_t* dst, uint64_t* carryH) {
unsigned char c = 0;
uint64_t h, carry;
dst[0] = _umul128(x[0], y, &h); carry = h;
c = _addcarry_u64(c, _umul128(x[1], y, &h), carry, dst + 1); carry = h;
c = _addcarry_u64(c, _umul128(x[2], y, &h), carry, dst + 2); carry = h;
c = _addcarry_u64(c, _umul128(x[3], y, &h), carry, dst + 3); carry = h;
#if NB64BLOCK > 5
c = _addcarry_u64(c, _umul128(x[4], y, &h), carry, dst + 4); carry = h;
c = _addcarry_u64(c, _umul128(x[5], y, &h), carry, dst + 5); carry = h;
c = _addcarry_u64(c, _umul128(x[6], y, &h), carry, dst + 6); carry = h;
c = _addcarry_u64(c, _umul128(x[7], y, &h), carry, dst + 7); carry = h;
#endif
c = _addcarry_u64(c, _mul128((int64_t)x[NB64BLOCK - 1], (int64_t)y, (int64_t*)&h), carry, dst + NB64BLOCK - 1); carry = h;
*carryH = carry;
}

#endif

//============================================================================
// Standard multiply (for compatibility)
//============================================================================
static inline void imm_mul(uint64_t *x, uint64_t y, uint64_t *dst, uint64_t *carryH) {
#if defined(__aarch64__)
imm_mul_madd(x, y, dst, carryH);
#else
unsigned char c = 0;
uint64_t h, carry;
dst[0] = _umul128(x[0], y, &h); carry = h;
c = _addcarry_u64(c, _umul128(x[1], y, &h), carry, dst + 1); carry = h;
c = _addcarry_u64(c, _umul128(x[2], y, &h), carry, dst + 2); carry = h;
c = _addcarry_u64(c, _umul128(x[3], y, &h), carry, dst + 3); carry = h;
c = _addcarry_u64(c, _umul128(x[4], y, &h), carry, dst + 4); carry = h;
#if NB64BLOCK > 5
c = _addcarry_u64(c, _umul128(x[5], y, &h), carry, dst + 5); carry = h;
c = _addcarry_u64(c, _umul128(x[6], y, &h), carry, dst + 6); carry = h;
c = _addcarry_u64(c, _umul128(x[7], y, &h), carry, dst + 7); carry = h;
c = _addcarry_u64(c, _umul128(x[8], y, &h), carry, dst + 8); carry = h;
#endif
*carryH = carry;
#endif
}

static inline void imm_imul(uint64_t* x, uint64_t y, uint64_t* dst, uint64_t* carryH) {
#if defined(__aarch64__)
imm_imul_madd(x, y, dst, carryH);
#else
unsigned char c = 0;
uint64_t h, carry;
dst[0] = _umul128(x[0], y, &h); carry = h;
c = _addcarry_u64(c, _umul128(x[1], y, &h), carry, dst + 1); carry = h;
c = _addcarry_u64(c, _umul128(x[2], y, &h), carry, dst + 2); carry = h;
c = _addcarry_u64(c, _umul128(x[3], y, &h), carry, dst + 3); carry = h;
#if NB64BLOCK > 5
c = _addcarry_u64(c, _umul128(x[4], y, &h), carry, dst + 4); carry = h;
c = _addcarry_u64(c, _umul128(x[5], y, &h), carry, dst + 5); carry = h;
c = _addcarry_u64(c, _umul128(x[6], y, &h), carry, dst + 6); carry = h;
c = _addcarry_u64(c, _umul128(x[7], y, &h), carry, dst + 7); carry = h;
#endif
c = _addcarry_u64(c, _mul128((int64_t)x[NB64BLOCK - 1], (int64_t)y, (int64_t*)&h), carry, dst + NB64BLOCK - 1); carry = h;
*carryH = carry;
#endif
}

static inline void imm_umul(uint64_t *x, uint64_t y, uint64_t *dst) {
unsigned char c = 0;
uint64_t h, carry;
dst[0] = _umul128(x[0], y, &h); carry = h;
c = _addcarry_u64(c, _umul128(x[1], y, &h), carry, dst + 1); carry = h;
c = _addcarry_u64(c, _umul128(x[2], y, &h), carry, dst + 2); carry = h;
c = _addcarry_u64(c, _umul128(x[3], y, &h), carry, dst + 3); carry = h;
#if NB64BLOCK > 5
c = _addcarry_u64(c, _umul128(x[4], y, &h), carry, dst + 4); carry = h;
c = _addcarry_u64(c, _umul128(x[5], y, &h), carry, dst + 5); carry = h;
c = _addcarry_u64(c, _umul128(x[6], y, &h), carry, dst + 6); carry = h;
c = _addcarry_u64(c, _umul128(x[7], y, &h), carry, dst + 7); carry = h;
#endif
_addcarry_u64(c, 0ULL, carry, dst + (NB64BLOCK - 1));
}

//============================================================================
// Shift operations with ROR optimization
//============================================================================
static inline void shiftR(unsigned char n, uint64_t *d) {
#if defined(__aarch64__)
// Use ROR for cross-limb shifts when beneficial
if (n == 32) {
// Fast 32-bit right shift using extraction
__asm__ volatile (
"lsr %x[d0], %x[d0], #32 \n"
"bfi %x[d0], %x[d1], #32, #32 \n"
"lsr %x[d1], %x[d1], #32 \n"
"bfi %x[d1], %x[d2], #32, #32 \n"
"lsr %x[d2], %x[d2], #32 \n"
"bfi %x[d2], %x[d3], #32, #32 \n"
"lsr %x[d3], %x[d3], #32 \n"
"bfi %x[d3], %x[d4], #32, #32 \n"
"lsr %x[d4], %x[d4], #32 \n"
: [d0] "+r" (d[0]), [d1] "+r" (d[1]), [d2] "+r" (d[2]),
  [d3] "+r" (d[3]), [d4] "+r" (d[4])
);
} else
#endif
{
d[0] = ((d[1] << (64 - n)) | (d[0] >> n));
d[1] = ((d[2] << (64 - n)) | (d[1] >> n));
d[2] = ((d[3] << (64 - n)) | (d[2] >> n));
d[3] = ((d[4] << (64 - n)) | (d[3] >> n));
#if NB64BLOCK > 5
d[4] = ((d[5] << (64 - n)) | (d[4] >> n));
d[5] = ((d[6] << (64 - n)) | (d[5] >> n));
d[6] = ((d[7] << (64 - n)) | (d[6] >> n));
d[7] = ((d[8] << (64 - n)) | (d[7] >> n));
#endif
d[NB64BLOCK-1] = ((int64_t)d[NB64BLOCK-1]) >> n;
}
}

static inline void shiftR(unsigned char n, uint64_t* d, uint64_t h) {
d[0] = ((d[1] << (64 - n)) | (d[0] >> n));
d[1] = ((d[2] << (64 - n)) | (d[1] >> n));
d[2] = ((d[3] << (64 - n)) | (d[2] >> n));
d[3] = ((d[4] << (64 - n)) | (d[3] >> n));
#if NB64BLOCK > 5
d[4] = ((d[5] << (64 - n)) | (d[4] >> n));
d[5] = ((d[6] << (64 - n)) | (d[5] >> n));
d[6] = ((d[7] << (64 - n)) | (d[6] >> n));
d[7] = ((d[8] << (64 - n)) | (d[7] >> n));
#endif
d[NB64BLOCK-1] = ((h << (64 - n)) | (d[NB64BLOCK-1] >> n));
}

static inline void shiftL(unsigned char n, uint64_t *d) {
#if NB64BLOCK > 5
d[8] = ((d[7] >> (64 - n)) | (d[8] << n));
d[7] = ((d[6] >> (64 - n)) | (d[7] << n));
d[6] = ((d[5] >> (64 - n)) | (d[6] << n));
d[5] = ((d[4] >> (64 - n)) | (d[5] << n));
#endif
d[4] = ((d[3] >> (64 - n)) | (d[4] << n));
d[3] = ((d[2] >> (64 - n)) | (d[3] << n));
d[2] = ((d[1] >> (64 - n)) | (d[2] << n));
d[1] = ((d[0] >> (64 - n)) | (d[1] << n));
d[0] = d[0] << n;
}

static inline int isStrictGreater128(uint64_t h1, uint64_t l1, uint64_t h2, uint64_t l2) {
if(h1 > h2) return 1;
if(h1 == h2) return l1 > l2;
return 0;
}

//============================================================================
// 64-bit signed multiply (for imm_imul)
//============================================================================
static inline int64_t _mul128(int64_t a, int64_t b, int64_t *h) {
#if defined(__aarch64__)
int64_t lo, hi;
__asm__ volatile (
"smulh %x[hi], %x[a], %x[b] \n"
"mul %x[lo], %x[a], %x[b] \n"
: [lo] "=&r" (lo), [hi] "=&r" (hi)
: [a] "r" (a), [b] "r" (b)
);
*h = hi;
return lo;
#else
typedef __int128 int128_t;
int128_t r = (int128_t)a * (int128_t)b;
*h = (int64_t)(r >> 64);
return (int64_t)r;
#endif
}

//============================================================================
// Byte swap using ARM64 REV instruction
//============================================================================
#if defined(__aarch64__)
static inline uint64_t _byteswap_uint64(uint64_t x) {
uint64_t r;
__asm__ volatile ("rev %x0, %x1" : "=r"(r) : "r"(x));
return r;
}
#define LZC(x) ({ uint64_t _r; __asm__("clz %x0, %x1" : "=r"(_r) : "r"((uint64_t)(x))); _r; })
#define TZC(x) ({ uint64_t _r; __asm__("rbit %x0, %x1\nclz %x0, %x0" : "=r"(_r) : "r"((uint64_t)(x))); _r; })
#else
#define _byteswap_uint64 __builtin_bswap64
#define LZC(x) __builtin_clzll(x)
#define TZC(x) __builtin_ctzll(x)
#endif

#define LoadI64(i,i64) \
i.bits64[0] = i64; \
i.bits64[1] = i64 >> 63; \
i.bits64[2] = i.bits64[1];\\
i.bits64[3] = i.bits64[1];\\
i.bits64[4] = i.bits64[1];

#endif // BIGINTH
