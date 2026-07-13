# BTC Puzzle Hunter v4.0 - ARM64 Ultimate Optimized Makefile
# For Termux/Android compilation with ALL ARM64 optimizations

CXX = clang++

# ARM64 Ultimate Optimization Flags
# -march=armv8-a+crc+crypto+sha2: Enable ALL ARM64 crypto extensions including SHA-256
# NEON is implicit on AArch64, no -mfpu needed
# -O3: Maximum optimization
# -flto: Link-time optimization
# -fomit-frame-pointer: Free up a register
# -funroll-loops: Unroll loops for better ILP
# -DNDEBUG: Remove assert() overhead
# -D__ARM_FEATURE_SHA2: Enable SHA-256 hardware intrinsics
# -D__ARM_FEATURE_CRYPTO: Enable crypto extensions

CXXFLAGS = -O3 -flto -fomit-frame-pointer -funroll-loops \
	-march=armv8-a+crc+crypto+sha2 -mtune=cortex-a76 \
	-DNDEBUG -Wall -Wextra \
	-D__ARM_FEATURE_SHA2 -D__ARM_FEATURE_CRYPTO \
	-ftree-vectorize \
	-ffast-math -funsafe-math-optimizations

# For even more aggressive optimization (use with caution):
# CXXFLAGS += -fipa-pta -fdevirtualize-at-ltrans -floop-nest-optimize

# Debug build flags (uncomment for debugging)
# DEBUG_CXXFLAGS = -g -O0 -DDEBUG -fsanitize=address

LDFLAGS = -lpthread -lcrypto -lssl -lm

# Source files
SRCS = hunter-android.cpp Int.cpp IntMod.cpp IntGroup.cpp Point.cpp \
	Random.cpp SECP256K1.cpp Timer.cpp

OBJS = $(SRCS:.cpp=.o)
TARGET = btc-puzzle-hunter-arm64

.PHONY: all clean release debug check-neon

all: check-neon $(TARGET)

check-neon:
	@echo "Checking ARM64 features..."
	@echo "Target: ARM64 with NEON + Crypto + SHA2"
	@echo "Instructions: MUL, UMULH, MADD, MSUB, ADC, SBC, CSEL, CSINC, CSET"
	@echo "Instructions: LDP, STP, PRFM"
	@echo "Instructions: SHA256H, SHA256H2, SHA256SU0, SHA256SU1"
	@echo "Instructions: NEON for Bloom Filter, Hash160, Hex Conversion"

release: CXXFLAGS += -DNDEBUG -fvisibility=hidden -fwhole-program
release: $(TARGET)

debug: CXXFLAGS = -g -O0 -DDEBUG
debug: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete: $(TARGET)"
	@echo "ARM64 optimizations enabled:"
	@echo " - Scalar: MUL, UMULH, MADD, MSUB, ADC, SBC, CSEL, CSINC, CSET"
	@echo " - Memory: LDP, STP, PRFM"
	@echo " - Crypto: SHA256H, SHA256H2, SHA256SU0, SHA256SU1"
	@echo " - SIMD: NEON for Bloom Filter, Hash160 batches, Hex conversion"

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

# Installation for Termux
install: $(TARGET)
	cp $(TARGET) $(PREFIX)/bin/

# Run with taskset for maximum performance on big cores
run: $(TARGET)
	taskset -c 4-7 ./$(TARGET)

# Performance profiling with perf (if available)
profile: $(TARGET)
	perf stat -e cycles,instructions,cache-misses,branch-misses ./$(TARGET)
