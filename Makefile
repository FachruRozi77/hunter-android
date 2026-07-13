# BTC Puzzle Hunter - ARM64 Optimized Makefile
# For Termux/Android compilation

CXX = clang++
CXXFLAGS = -O3 -flto -fomit-frame-pointer -funroll-loops \
           -march=armv8-a+crc+crypto -mtune=cortex-a76 \
           -DNDEBUG -Wall -Wextra

# For maximum performance, use:
# -ffast-math -funsafe-math-optimizations (if no strict IEEE needed)

LDFLAGS = -lpthread -lcrypto -lssl -lm

# Source files
SRCS = hunter-android.cpp Int.cpp IntMod.cpp IntGroup.cpp Point.cpp \
       Random.cpp SECP256K1.cpp Timer.cpp

OBJS = $(SRCS:.cpp=.o)
TARGET = btc-puzzle-hunter

.PHONY: all clean release debug

all: $(TARGET)

release: CXXFLAGS += -DNDEBUG -fvisibility=hidden
release: $(TARGET)

debug: CXXFLAGS = -g -O0 -DDEBUG
debug: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

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
