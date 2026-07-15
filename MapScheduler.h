#ifndef MAPSCHEDULER_H
#define MAPSCHEDULER_H

#include "MapRange.h"
#include "Int.h"
#include "FastRandom.h"
#include <vector>
#include <mutex>
#include <cstdint>
#include <string>

enum class ScanMode {
    SEQUENTIAL,
    RANDOM
};

class MapScheduler {
public:
    MapScheduler();
    ~MapScheduler();

    // Phase 2: Build map ranges
    void initializeMapRanges(const Int& startRange, const Int& endRange);

    // Phase 5: Worker API
    bool getNextSequentialMap(MapRange& out);
    bool getRandomMap(MapRange& out, FastRandom& rng);
    void finishMap(uint64_t mapId);
    void assignMap(uint64_t mapId);

    // Phase 7: Progress
    bool saveProgress(const std::string& filename, ScanMode mode,
                      uint64_t currentMapId, const Int& currentOffset,
                      const std::string& startHex, const std::string& endHex,
                      const std::vector<std::string>& targetHashes);
    bool loadProgress(const std::string& filename, ScanMode& mode,
                      uint64_t& currentMapId, Int& currentOffset,
                      std::string& startHex, std::string& endHex,
                      std::vector<std::string>& targetHashes);

    // Stats
    uint64_t getTotalMaps() const;
    uint64_t getCompletedMaps() const;
    uint64_t getRemainingMaps() const;
    uint64_t getMapSize() const;
    double getOverallPercent() const;
    bool isComplete() const;
    ScanMode getMode() const { return mode; }
    void setMode(ScanMode m) { mode = m; }

    // Bitmap access for progress
    const std::vector<bool>& getFinishedBitmap() const { return finishedBitmap; }

private:
    std::vector<MapRange> mapRanges;
    std::vector<bool> finishedBitmap;
    std::mutex schedulerMutex;
    Int startRange;
    Int endRange;
    Int mapSize;
    uint64_t totalMaps;
    ScanMode mode;

    void computeMapRanges(const Int& totalElements);
};

#endif // MAPSCHEDULER_H
