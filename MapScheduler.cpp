#include "MapScheduler.h"
#include "FastRandom.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

MapScheduler::MapScheduler() : totalMaps(0), mode(ScanMode::SEQUENTIAL) {}

MapScheduler::~MapScheduler() {}

void MapScheduler::initializeMapRanges(const Int& start, const Int& end) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    startRange = start;
    endRange = end;

    Int totalElements;
    totalElements.Sub(&end, &start);
    totalElements.AddOne();

    computeMapRanges(totalElements);
}

void MapScheduler::computeMapRanges(const Int& totalElements) {
    // n = floor(sqrt(TotalElements))
    double approx = totalElements.ToDouble();
    if (approx < 1.0) approx = 1.0;
    uint64_t n = (uint64_t)std::sqrt(approx);
    if (n < 1) n = 1;

    // Properly set mapSize as an Int from uint64_t
    mapSize.SetInt32(0);
    mapSize.SetQWord(0, n);   // <-- Use SetQWord instead of SetInt32

    // map_count = ceil(totalElements / mapSize)
    Int temp;
    temp.Set(&totalElements);
    temp.Add(&mapSize);
    temp.SubOne();
    Int mapCountInt;
    mapCountInt.Set(&temp);
    mapCountInt.Div(&mapSize, nullptr);
    totalMaps = mapCountInt.GetInt32();
    if (totalMaps == 0) totalMaps = 1;

    mapRanges.clear();
    finishedBitmap.clear();
    finishedBitmap.resize(totalMaps, false);

    Int currentStart;
    currentStart.Set(&startRange);

    for (uint64_t i = 0; i < totalMaps; i++) {
        MapRange mr;
        mr.id = i;
        mr.start.Set(&currentStart);

        Int mapEnd;
        mapEnd.Set(&currentStart);
        mapEnd.Add(&mapSize);
        mapEnd.SubOne();

        // Last map or beyond endRange
        if (i == totalMaps - 1 || mapEnd.IsGreater(&endRange)) {
            mapEnd.Set(&endRange);
        }

        mr.end.Set(&mapEnd);
        mr.finished = false;
        mr.assigned = false;
        mr.checked = 0;

        mapRanges.push_back(mr);

        // Next start = this end + 1
        currentStart.Set(&mapEnd);
        currentStart.AddOne();
    }
}

bool MapScheduler::getNextSequentialMap(MapRange& out) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    for (uint64_t i = 0; i < totalMaps; i++) {
        if (!mapRanges[i].finished && !mapRanges[i].assigned) {
            mapRanges[i].assigned = true;
            out = mapRanges[i];
            return true;
        }
    }
    return false;
}

bool MapScheduler::getRandomMap(MapRange& out, FastRandom& rng) {
    std::lock_guard<std::mutex> lock(schedulerMutex);

    // Collect unfinished, unassigned map IDs
    std::vector<uint64_t> available;
    for (uint64_t i = 0; i < totalMaps; i++) {
        if (!mapRanges[i].finished && !mapRanges[i].assigned) {
            available.push_back(i);
        }
    }

    if (available.empty()) return false;

    uint64_t idx = rng.next() % available.size();
    uint64_t mapId = available[idx];
    mapRanges[mapId].assigned = true;
    out = mapRanges[mapId];
    return true;
}

void MapScheduler::finishMap(uint64_t mapId) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    if (mapId < totalMaps) {
        mapRanges[mapId].finished = true;
        mapRanges[mapId].assigned = false;
        finishedBitmap[mapId] = true;
    }
}

void MapScheduler::assignMap(uint64_t mapId) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    if (mapId < totalMaps) {
        mapRanges[mapId].assigned = true;
    }
}

uint64_t MapScheduler::getTotalMaps() const {
    return totalMaps;
}

uint64_t MapScheduler::getCompletedMaps() const {
    uint64_t count = 0;
    for (bool b : finishedBitmap) if (b) count++;
    return count;
}

uint64_t MapScheduler::getRemainingMaps() const {
    return totalMaps - getCompletedMaps();
}

uint64_t MapScheduler::getMapSize() const {
    // Approximate
    if (mapSize.GetBitLength() <= 64) {
        return mapSize.bits64[0];
    }
    return 0xFFFFFFFFULL;
}

double MapScheduler::getOverallPercent() const {
    if (totalMaps == 0) return 0.0;
    return (double)getCompletedMaps() / (double)totalMaps * 100.0;
}

bool MapScheduler::isComplete() const {
    return getCompletedMaps() >= totalMaps;
}

bool MapScheduler::saveProgress(const std::string& filename, ScanMode saveMode,
                              uint64_t currentMapId, const Int& currentOffset,
                              const std::string& startHex, const std::string& endHex,
                              const std::vector<std::string>& targetHashes) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    std::ofstream fs(filename);
    if (!fs) return false;

    fs << "Version=2\n";
    fs << "Mode=" << (saveMode == ScanMode::SEQUENTIAL ? "Sequential" : "Random") << "\n";
    fs << "StartRange=" << startRange.GetBase16() << "\n";
    fs << "EndRange=" << endRange.GetBase16() << "\n";
    fs << "MapCount=" << totalMaps << "\n";
    fs << "Interval=" << getMapSize() << "\n";
    fs << "CompletedMaps=" << getCompletedMaps() << "\n";
    fs << "CurrentMap=" << currentMapId << "\n";
    fs << "CurrentOffset=" << currentOffset.GetBase16() << "\n";

    // Bitmap
    fs << "Bitmap=";
    for (bool b : finishedBitmap) {
        fs << (b ? '1' : '0');
    }
    fs << "\n";

    // Targets
    fs << "TargetCount=" << targetHashes.size() << "\n";
    for (const auto& h : targetHashes) {
        fs << "Target=" << h << "\n";
    }

    fs.flush();
    return fs.good();
}

bool MapScheduler::loadProgress(const std::string& filename, ScanMode& loadMode,
                                uint64_t& currentMapId, Int& currentOffset,
                                std::string& loadStartHex, std::string& loadEndHex,
                                std::vector<std::string>& targetHashes) {
    std::ifstream fs(filename);
    if (!fs) return false;

    std::string line;
    std::string modeStr;
    uint64_t loadedMapCount = 0;

    while (std::getline(fs, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        if (key == "Version") {
            if (val != "2") return false;
        } else if (key == "Mode") {
            modeStr = val;
        } else if (key == "StartRange") {
            loadStartHex = val;
        } else if (key == "EndRange") {
            loadEndHex = val;
        } else if (key == "MapCount") {
            loadedMapCount = std::stoull(val);
        } else if (key == "CurrentMap") {
            currentMapId = std::stoull(val);
        } else if (key == "CurrentOffset") {
            currentOffset.SetBase16(const_cast<char*>(val.c_str()));
        } else if (key == "Bitmap") {
            finishedBitmap.clear();
            for (char c : val) {
                finishedBitmap.push_back(c == '1');
            }
        } else if (key == "Target") {
            targetHashes.push_back(val);
        }
    }

    loadMode = (modeStr == "Random") ? ScanMode::RANDOM : ScanMode::SEQUENTIAL;
    return true;
}
