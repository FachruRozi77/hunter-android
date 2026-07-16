#ifndef MAPSCHEDULER_H
#define MAPSCHEDULER_H

#include "MapRange.h"
#include "Int.h"
#include "FastRandom.h"
#include <vector>
#include <mutex>
#include <cstdint>
#include <string>
#include <set>
#include <algorithm>
#include <fstream>
#include <iostream>

enum class ScanMode {
    SEQUENTIAL,
    RANDOM
};

class CooperativeMapScheduler {
public:
    CooperativeMapScheduler();
    ~CooperativeMapScheduler();

    void initialize(const Int& start, const Int& end);

    // Get the next batch of private keys from the CURRENT shared map.
    // Returns number of keys filled (0 if current map is exhausted).
    // When a map is exhausted, this automatically advances to the next map.
    int getNextBatch(Int* outKeys, int maxCount);

    uint64_t getCurrentMapId() const;
    uint64_t getTotalMaps() const;
    uint64_t getCompletedMaps() const;
    uint64_t getMapSize() const;
    double getOverallPercent() const;
    bool isComplete() const;

    ScanMode getMode() const;
    void setMode(ScanMode m);

    MapRange getCurrentMapRange() const;
    Int getCurrentOffset() const;

    bool saveProgress(const std::string& filename, ScanMode saveMode,
                      const Int& currentOffset,
                      const std::string& startHex, const std::string& endHex,
                      const std::vector<std::string>& targetHashes);
    bool loadProgress(const std::string& filename, ScanMode& loadMode,
                      uint64_t& loadedCurrentMap, Int& loadedOffset,
                      std::string& loadStartHex, std::string& loadEndHex,
                      std::vector<std::string>& targetHashes);

private:
    Int startRange;
    Int endRange;
    Int mapSize;
    uint64_t totalMaps;
    ScanMode mode;

    uint64_t currentMapId;
    Int currentMapStart;
    Int currentMapEnd;
    Int currentOffset;
    bool mapFinished;

    std::set<uint64_t> finishedMaps;
    uint64_t nextSequentialHint;
    mutable std::mutex mutex;

    static Int integerSqrt(const Int& n);
    void computeCurrentMap();
    void advanceToNextMap();
};

#endif // MAPSCHEDULER_H
