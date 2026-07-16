# BTC Puzzle Hunter v4.0 - Map Scheduler Edition
# For Termux/Android compilation

CXX = clang++
CXXFLAGS = -O3 -flto -fomit-frame-pointer -funroll-loops \
           -march=armv8-a+crc+crypto -mtune=native \
           -DNDEBUG -Wall -Wextra -fprofile-use=default_10523545445524568249_0.profraw

LDFLAGS = -lpthread -lcrypto -lssl -lm

# Source files - NEW files added
SRCS = hunter-android.cpp \
       Int.cpp IntMod.cpp IntGroup.cpp Point.cpp \
       Random.cpp SECP256K1.cpp Timer.cpp \
       MapScheduler.cpp Hash160.cpp FastRandom.cpp

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
	rm -f $(OBJS) $(TARGET) Progress.dat candidates.txt found.txt

install: $(TARGET)
	cp $(TARGET) $(PREFIX)/bin/

run: $(TARGET)
	taskset -c 4-7 ./$(TARGET)
