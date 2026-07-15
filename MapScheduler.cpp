#include "MapScheduler.h"
#include "FastRandom.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

// FIX #3: Integer square root for Int class (Newton's method)
// Used instead of double sqrt() to avoid precision loss on 256-bit values.
static Int integerSqrt(const Int& n) {
    if (n.IsZero() || n.IsOne()) {
        Int r; r.Set(&n); return r;
    }
    
    Int x; 
    x.Set(&n);
    x.ShiftR(1);  // x = n / 2
    
    Int two; 
    two.SetInt32(2);
    
    Int last; 
    last.Set(&x);
    
    for (int iter = 0; iter < 300; ++iter) {
        // q = n / x
        Int q, rmd;
        q.Set(&n);
        q.Div(&x, &rmd);
        
        // sum = x + q
        Int sum;
        sum.Add(&x, &q);
        
        // sum = sum / 2
        sum.ShiftR(1);
        
        if (sum.IsEqual(&x) || sum.IsEqual(&last)) {
            // Verify floor sqrt: if sum*sum > n, decrement
            Int sq;
            sq.Mult(&sum, &sum);
            if (sq.IsGreater(&n)) {
                sum.SubOne();
            }
            return sum;
        }
        last.Set(&x);
        x.Set(&sum);
    }
    
    // Fallback verification
    Int sq;
    sq.Mult(&x, &x);
    if (sq.IsGreater(&n)) x.SubOne();
    return x;
}

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
    
    // FIX #13: Apply bitmap loaded from progress file now that mapRanges exist
    if (!pendingBitmap.empty()) {
        if (pendingBitmap.size() == finishedBitmap.size()) {
            restoreFinishedBitmap(pendingBitmap);
        } else {
            std::cerr << "[RESUME] Pending bitmap size mismatch: file=" 
                      << pendingBitmap.size() << " expected=" 
                      << finishedBitmap.size() << "\n";
        }
        pendingBitmap.clear();
    }
}

void MapScheduler::computeMapRanges(const Int& totalElements) {
    // FIX #3: Use integer square root instead of double to prevent precision loss
    Int sqrtInt = integerSqrt(totalElements);
    uint64_t n = 1;
    if (sqrtInt.GetBitLength() <= 64) {
        n = sqrtInt.bits64[0];
    } else {
        n = 0xFFFFFFFFFFFFFFFFULL;
    }
    if (n < 1) n = 1;

    mapSize.SetInt32(0);
    mapSize.SetQWord(0, n);

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

        if (i == totalMaps - 1 || mapEnd.IsGreater(&endRange)) {
            mapEnd.Set(&endRange);
        }

        mr.end.Set(&mapEnd);
        mr.finished = false;
        mr.assigned = false;
        mr.checked = 0;

        mapRanges.push_back(mr);

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

// FIX #6: Eliminate per-call vector allocation; scan-forward from random start
bool MapScheduler::getRandomMap(MapRange& out, FastRandom& rng) {
    std::lock_guard<std::mutex> lock(schedulerMutex);

    uint64_t remaining = getRemainingMaps();
    if (remaining == 0) return false;

    uint64_t startIdx = rng.next() % totalMaps;
    uint64_t idx = startIdx;

    do {
        if (!mapRanges[idx].finished && !mapRanges[idx].assigned) {
            mapRanges[idx].assigned = true;
            out = mapRanges[idx];
            return true;
        }
        idx = (idx + 1) % totalMaps;
    } while (idx != startIdx);

    return false;
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

void MapScheduler::restoreFinishedBitmap(const std::vector<bool>& bitmap) {
    std::lock_guard<std::mutex> lock(schedulerMutex);
    if (bitmap.size() != finishedBitmap.size()) {
        std::cerr << "[RESUME] Bitmap size mismatch: file=" << bitmap.size() 
                  << " expected=" << finishedBitmap.size() << "\n";
        return;
    }
    finishedBitmap = bitmap;
    for (size_t i = 0; i < mapRanges.size() && i < bitmap.size(); i++) {
        mapRanges[i].finished = bitmap[i];
        mapRanges[i].assigned = false;
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
    if (mapSize.GetBitLength() <= 64) {
        return mapSize.bits64[0];
    }
    return 0xFFFFFFFFFFFFFFFFULL;
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

    fs << "Bitmap=";
    for (bool b : finishedBitmap) {
        fs << (b ? '1' : '0');
    }
    fs << "\n";

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
            // FIX #13: Store in pendingBitmap to be applied after initializeMapRanges
            pendingBitmap.clear();
            for (char c : val) {
                pendingBitmap.push_back(c == '1');
            }
        } else if (key == "Target") {
            targetHashes.push_back(val);
        }
    }

    loadMode = (modeStr == "Random") ? ScanMode::RANDOM : ScanMode::SEQUENTIAL;
    return true;
}
