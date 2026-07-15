#include "MapScheduler.h"
#include "FastRandom.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

// Integer square root for Int class (Newton's method)
static Int integerSqrt(const Int& n) {
    Int nCopy;
    nCopy.Set(const_cast<Int*>(&n));
    
    if (nCopy.IsZero() || nCopy.IsOne()) {
        return nCopy;
    }
    
    Int x;
    x.Set(&nCopy);
    x.ShiftR(1);
    
    Int last;
    last.Set(&x);
    
    for (int iter = 0; iter < 300; ++iter) {
        Int q, rmd;
        q.Set(&nCopy);
        q.Div(&x, &rmd);
        
        Int sum;
        sum.Add(&x, &q);
        sum.ShiftR(1);
        
        if (sum.IsEqual(&x) || sum.IsEqual(&last)) {
            Int sq;
            sq.Mult(&sum, &sum);
            if (sq.IsGreater(&nCopy)) {
                sum.SubOne();
            }
            return sum;
        }
        last.Set(&x);
        x.Set(&sum);
    }
    
    Int sq;
    sq.Mult(&x, &x);
    if (sq.IsGreater(&nCopy)) x.SubOne();
    return x;
}

MapScheduler::MapScheduler() : totalMaps(0), mode(ScanMode::SEQUENTIAL), nextSequentialHint(0) {}

MapScheduler::~MapScheduler() {}

void MapScheduler::computeMapRanges(const Int& totalElements) {
    Int sqrtInt = integerSqrt(totalElements);
    uint64_t n = 1;
    Int sqrtCopy;
    sqrtCopy.Set(&sqrtInt);
    if (sqrtCopy.GetBitLength() <= 64) {
        n = sqrtInt.bits64[0];
    } else {
        n = 0xFFFFFFFFFFFFFFFFULL;
    }
    if (n < 1) n = 1;

    mapSize.SetInt32(0);
    mapSize.SetQWord(0, n);

    Int temp;
    temp.Set(const_cast<Int*>(&totalElements));
    temp.Add(&mapSize);
    temp.SubOne();
    Int mapCountInt;
    mapCountInt.Set(&temp);
    mapCountInt.Div(&mapSize, nullptr);
    totalMaps = mapCountInt.GetInt32();
    if (totalMaps == 0) totalMaps = 1;
}

void MapScheduler::initializeMapRanges(const Int& start, const Int& end) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    startRange.Set(const_cast<Int*>(&start));
    endRange.Set(const_cast<Int*>(&end));

    Int totalElements;
    totalElements.Sub(const_cast<Int*>(&end), const_cast<Int*>(&start));
    totalElements.AddOne();

    computeMapRanges(totalElements);
    nextSequentialHint = 0;
}

MapRange MapScheduler::computeMapRange(uint64_t mapId) const {
    MapRange mr;
    mr.id = mapId;
    
    // Calculate start: startRange + (mapId * mapSize)
    mr.start.Set(const_cast<Int*>(&startRange));
    
    if (mapId > 0) {
        Int offset;
        offset.SetInt32(0);
        offset.SetQWord(0, mapId);
        offset.Mult(&offset, const_cast<Int*>(&mapSize));
        mr.start.Add(&offset);
    }
    
    // Calculate end: start + mapSize - 1
    mr.end.Set(&mr.start);
    mr.end.Add(const_cast<Int*>(&mapSize));
    mr.end.SubOne();
    
    // Clamp to global end
    if (mr.end.IsGreater(const_cast<Int*>(&endRange))) {
        mr.end.Set(const_cast<Int*>(&endRange));
    }
    
    mr.finished = false;
    mr.assigned = false;
    mr.checked = 0;
    
    return mr;
}

uint64_t MapScheduler::findNextSequentialMapId() {
    // Find the smallest map ID that is neither finished nor assigned
    // This naturally fills gaps in the finished sequence
    
    uint64_t candidate = nextSequentialHint;
    while (candidate < totalMaps) {
        if (finishedMaps.find(candidate) == finishedMaps.end() &&
            assignedMaps.find(candidate) == assignedMaps.end()) {
            nextSequentialHint = candidate + 1;
            return candidate;
        }
        candidate++;
    }
    
    // If we reached the end, scan from beginning to find any gaps
    for (uint64_t i = 0; i < totalMaps; i++) {
        if (finishedMaps.find(i) == finishedMaps.end() &&
            assignedMaps.find(i) == assignedMaps.end()) {
            nextSequentialHint = i + 1;
            return i;
        }
    }
    
    return totalMaps; // No maps available
}

bool MapScheduler::getNextSequentialMap(MapRange& out) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    
    uint64_t mapId = findNextSequentialMapId();
    if (mapId >= totalMaps) {
        return false;
    }
    
    assignedMaps.insert(mapId);
    out = computeMapRange(mapId);
    out.assigned = true;
    return true;
}

bool MapScheduler::getRandomMap(MapRange& out, FastRandom& rng) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    
    // Inline remaining calculation to avoid recursive mutex deadlock
    uint64_t remaining = totalMaps - finishedMaps.size() - assignedMaps.size();
    if (remaining == 0) return false;
    
    // If remaining is small, enumerate and pick
    if (remaining <= 1000) {
        std::vector<uint64_t> available;
        available.reserve(remaining);
        for (uint64_t i = 0; i < totalMaps; i++) {
            if (finishedMaps.find(i) == finishedMaps.end() &&
                assignedMaps.find(i) == assignedMaps.end()) {
                available.push_back(i);
                if (available.size() >= remaining) break;
            }
        }
        if (available.empty()) return false;
        uint64_t idx = rng.next() % available.size();
        uint64_t mapId = available[idx];
        assignedMaps.insert(mapId);
        out = computeMapRange(mapId);
        out.assigned = true;
        return true;
    }
    
    // For large remaining, use probabilistic sampling
    uint64_t attempts = 0;
    const uint64_t maxAttempts = 1000;
    
    while (attempts < maxAttempts) {
        uint64_t mapId = rng.next() % totalMaps;
        if (finishedMaps.find(mapId) == finishedMaps.end() &&
            assignedMaps.find(mapId) == assignedMaps.end()) {
            assignedMaps.insert(mapId);
            out = computeMapRange(mapId);
            out.assigned = true;
            return true;
        }
        attempts++;
    }
    
    // Fallback: scan from random start
    uint64_t startIdx = rng.next() % totalMaps;
    for (uint64_t i = 0; i < totalMaps; i++) {
        uint64_t mapId = (startIdx + i) % totalMaps;
        if (finishedMaps.find(mapId) == finishedMaps.end() &&
            assignedMaps.find(mapId) == assignedMaps.end()) {
            assignedMaps.insert(mapId);
            out = computeMapRange(mapId);
            out.assigned = true;
            return true;
        }
    }
    
    return false;
}

void MapScheduler::finishMap(uint64_t mapId) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    if (mapId < totalMaps) {
        finishedMaps.insert(mapId);
        assignedMaps.erase(mapId);
    }
}

void MapScheduler::assignMap(uint64_t mapId) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    if (mapId < totalMaps) {
        assignedMaps.insert(mapId);
    }
}

void MapScheduler::unassignMap(uint64_t mapId) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    assignedMaps.erase(mapId);
}

uint64_t MapScheduler::getTotalMaps() const {
    return totalMaps;
}

uint64_t MapScheduler::getCompletedMaps() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(schedulerMutex));
    return finishedMaps.size();
}

uint64_t MapScheduler::getRemainingMaps() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(schedulerMutex));
    return totalMaps - finishedMaps.size() - assignedMaps.size();
}

uint64_t MapScheduler::getMapSize() const {
    Int mapSizeCopy;
    mapSizeCopy.Set(const_cast<Int*>(&mapSize));
    if (mapSizeCopy.GetBitLength() <= 64) {
        return mapSize.bits64[0];
    }
    return 0xFFFFFFFFFFFFFFFFULL;
}

double MapScheduler::getOverallPercent() const {
    if (totalMaps == 0) return 0.0;
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(schedulerMutex));
    return (double)finishedMaps.size() / (double)totalMaps * 100.0;
}

bool MapScheduler::isComplete() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(schedulerMutex));
    return finishedMaps.size() >= totalMaps;
}

bool MapScheduler::isMapFinished(uint64_t mapId) const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(schedulerMutex));
    return finishedMaps.find(mapId) != finishedMaps.end();
}

bool MapScheduler::isMapAssigned(uint64_t mapId) const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(schedulerMutex));
    return assignedMaps.find(mapId) != assignedMaps.end();
}

bool MapScheduler::saveProgress(const std::string& filename, ScanMode saveMode,
                              uint64_t currentMapId, const Int& currentOffset,
                              const std::string& startHex, const std::string& endHex,
                              const std::vector<std::string>& targetHashes) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    std::ofstream fs(filename);
    if (!fs) return false;

    fs << "Version=3\n";
    fs << "Mode=" << (saveMode == ScanMode::SEQUENTIAL ? "Sequential" : "Random") << "\n";
    fs << "StartRange=" << startRange.GetBase16() << "\n";
    fs << "EndRange=" << endRange.GetBase16() << "\n";
    fs << "MapSize=" << getMapSize() << "\n";
    fs << "TotalMaps=" << totalMaps << "\n";
    fs << "FinishedCount=" << finishedMaps.size() << "\n";
    
    for (uint64_t mapId : finishedMaps) {
        fs << "Finished=" << mapId << "\n";
    }
    
    fs << "CurrentMap=" << currentMapId << "\n";
    
    Int offsetCopy;
    offsetCopy.Set(const_cast<Int*>(&currentOffset));
    fs << "CurrentOffset=" << offsetCopy.GetBase16() << "\n";

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
    uint64_t loadedMapSize = 0;
    uint64_t loadedTotalMaps = 0;
    uint64_t loadedFinishedCount = 0;
    uint64_t finishedRead = 0;

    finishedMaps.clear();
    assignedMaps.clear();

    while (std::getline(fs, line)) {
        // Remove trailing \r if present (Windows line endings)
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        if (key == "Version") {
            if (val != "3") {
                std::cerr << "[RESUME] Old progress file format (Version=" << val 
                          << "). Please start fresh or convert.\n";
                return false;
            }
        } else if (key == "Mode") {
            modeStr = val;
        } else if (key == "StartRange") {
            loadStartHex = val;
            startRange.SetBase16(const_cast<char*>(val.c_str()));
        } else if (key == "EndRange") {
            loadEndHex = val;
            endRange.SetBase16(const_cast<char*>(val.c_str()));
        } else if (key == "MapSize") {
            loadedMapSize = std::stoull(val);
            mapSize.SetInt32(0);
            mapSize.SetQWord(0, loadedMapSize);
        } else if (key == "TotalMaps") {
            loadedTotalMaps = std::stoull(val);
            totalMaps = loadedTotalMaps;
        } else if (key == "FinishedCount") {
            loadedFinishedCount = std::stoull(val);
        } else if (key == "Finished") {
            uint64_t mapId = std::stoull(val);
            finishedMaps.insert(mapId);
            finishedRead++;
        } else if (key == "CurrentMap") {
            currentMapId = std::stoull(val);
        } else if (key == "CurrentOffset") {
            currentOffset.SetBase16(const_cast<char*>(val.c_str()));
        } else if (key == "Target") {
            targetHashes.push_back(val);
        }
    }

    if (finishedRead != loadedFinishedCount) {
        std::cerr << "[RESUME] Warning: Expected " << loadedFinishedCount 
                  << " finished maps but read " << finishedRead << "\n";
    }

    // Recompute nextSequentialHint based on loaded finished maps
    nextSequentialHint = 0;
    while (nextSequentialHint < totalMaps && 
           finishedMaps.find(nextSequentialHint) != finishedMaps.end()) {
        nextSequentialHint++;
    }

    loadMode = (modeStr == "Random") ? ScanMode::RANDOM : ScanMode::SEQUENTIAL;
    return true;
}
