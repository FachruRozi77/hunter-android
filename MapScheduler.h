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

enum class ScanMode {
    SEQUENTIAL,
    RANDOM
};

class MapScheduler {
public:
    MapScheduler();
    ~MapScheduler();

    void initializeMapRanges(const Int& startRange, const Int& endRange);

    // Compute a MapRange on-the-fly from map ID (no storage)
    MapRange computeMapRange(uint64_t mapId) const;

    bool getNextSequentialMap(MapRange& out);
    bool getRandomMap(MapRange& out, FastRandom& rng);
    void finishMap(uint64_t mapId);
    void assignMap(uint64_t mapId);
    void unassignMap(uint64_t mapId);

    bool saveProgress(const std::string& filename, ScanMode mode,
                      uint64_t currentMapId, const Int& currentOffset,
                      const std::string& startHex, const std::string& endHex,
                      const std::vector<std::string>& targetHashes);
    bool loadProgress(const std::string& filename, ScanMode& mode,
                      uint64_t& currentMapId, Int& currentOffset,
                      std::string& startHex, std::string& endHex,
                      std::vector<std::string>& targetHashes);

    uint64_t getTotalMaps() const;
    uint64_t getCompletedMaps() const;
    uint64_t getRemainingMaps() const;
    uint64_t getMapSize() const;
    double getOverallPercent() const;
    bool isComplete() const;
    ScanMode getMode() const { return mode; }
    void setMode(ScanMode m) { mode = m; }

    bool isMapFinished(uint64_t mapId) const;
    bool isMapAssigned(uint64_t mapId) const;

private:
    // No vector<MapRange> - maps are computed on-the-fly
    std::set<uint64_t> finishedMaps;    // Sorted set of finished map IDs
    std::set<uint64_t> assignedMaps;    // Currently assigned (in-flight) map IDs
    std::mutex schedulerMutex;
    Int startRange;
    Int endRange;
    Int mapSize;
    uint64_t totalMaps;
    ScanMode mode;

    // For efficient sequential gap-finding
    uint64_t nextSequentialHint;

    void computeMapRanges(const Int& totalElements);
    uint64_t findNextSequentialMapId();
};

#endif // MAPSCHEDULER_H
