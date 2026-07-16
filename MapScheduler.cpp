#include "MapScheduler.h"
#include <chrono>

CooperativeMapScheduler::CooperativeMapScheduler()
    : totalMaps(0), mode(ScanMode::SEQUENTIAL),
      currentMapId(0), mapFinished(false), nextSequentialHint(0) {}

CooperativeMapScheduler::~CooperativeMapScheduler() {}

void CooperativeMapScheduler::initialize(const Int& start, const Int& end) {
    std::lock_guard<std::mutex> lock(mutex);
    startRange.Set(const_cast<Int*>(&start));
    endRange.Set(const_cast<Int*>(&end));

    Int totalElements;
    totalElements.Sub(const_cast<Int*>(&end), const_cast<Int*>(&start));
    totalElements.AddOne();

    // Compute map size = sqrt(totalElements)
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

    finishedMaps.clear();
    currentMapId = 0;
    mapFinished = false;
    nextSequentialHint = 0;

    computeCurrentMap();
}

int CooperativeMapScheduler::getNextBatch(Int* outKeys, int maxCount) {
    std::lock_guard<std::mutex> lock(mutex);

    while (mapFinished || currentMapId >= totalMaps) {
        if (currentMapId >= totalMaps) {
            return 0;
        }
        finishedMaps.insert(currentMapId);
        advanceToNextMap();
        if (currentMapId >= totalMaps) {
            return 0;
        }
    }

    int count = 0;
    for (int i = 0; i < maxCount; i++) {
        if (currentOffset.IsGreater(&currentMapEnd)) {
            mapFinished = true;
            finishedMaps.insert(currentMapId);
            break;
        }
        outKeys[count].Set(&currentOffset);
        count++;
        currentOffset.AddOne();
    }
    return count;
}

uint64_t CooperativeMapScheduler::getCurrentMapId() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex));
    return currentMapId;
}

uint64_t CooperativeMapScheduler::getCompletedMaps() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex));
    return finishedMaps.size();
}

uint64_t CooperativeMapScheduler::getMapSize() const {
    Int copy;
    copy.Set(const_cast<Int*>(&mapSize));
    if (copy.GetBitLength() <= 64) return mapSize.bits64[0];
    return 0xFFFFFFFFFFFFFFFFULL;
}

double CooperativeMapScheduler::getOverallPercent() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex));
    if (totalMaps == 0) return 0.0;
    return (double)finishedMaps.size() / (double)totalMaps * 100.0;
}

bool CooperativeMapScheduler::isComplete() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex));
    return finishedMaps.size() >= totalMaps;
}

ScanMode CooperativeMapScheduler::getMode() const { return mode; }

void CooperativeMapScheduler::setMode(ScanMode m) { mode = m; }

MapRange CooperativeMapScheduler::getCurrentMapRange() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex));
    MapRange mr;
    mr.id = currentMapId;
    mr.start.Set(const_cast<Int*>(&currentMapStart));
    mr.end.Set(const_cast<Int*>(&currentMapEnd));
    return mr;
}

Int CooperativeMapScheduler::getCurrentOffset() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex));
    Int copy;
    copy.Set(const_cast<Int*>(&currentOffset));
    return copy;
}

bool CooperativeMapScheduler::saveProgress(const std::string& filename, ScanMode saveMode,
                      const Int& currentOffset,
                      const std::string& startHex, const std::string& endHex,
                      const std::vector<std::string>& targetHashes) {
    std::lock_guard<std::mutex> lock(mutex);
    std::ofstream fs(filename);
    if (!fs) return false;

    fs << "Version=4\n";
    fs << "Mode=" << (saveMode == ScanMode::SEQUENTIAL ? "Sequential" : "Random") << "\n";
    fs << "StartRange=" << startRange.GetBase16() << "\n";
    fs << "EndRange=" << endRange.GetBase16() << "\n";
    fs << "MapSize=" << getMapSize() << "\n";
    fs << "TotalMaps=" << totalMaps << "\n";
    fs << "CurrentMap=" << currentMapId << "\n";

    Int offsetCopy;
    offsetCopy.Set(const_cast<Int*>(&currentOffset));
    fs << "CurrentOffset=" << offsetCopy.GetBase16() << "\n";

    fs << "FinishedCount=" << finishedMaps.size() << "\n";
    for (uint64_t id : finishedMaps) {
        fs << "Finished=" << id << "\n";
    }

    fs << "TargetCount=" << targetHashes.size() << "\n";
    for (const auto& h : targetHashes) {
        fs << "Target=" << h << "\n";
    }

    fs.flush();
    return fs.good();
}

bool CooperativeMapScheduler::loadProgress(const std::string& filename, ScanMode& loadMode,
                      uint64_t& loadedCurrentMap, Int& loadedOffset,
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

    while (std::getline(fs, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        if (key == "Version") {
            if (val != "4") {
                std::cerr << "[RESUME] Old progress file format (Version=" << val
                          << "). Please start fresh.\n";
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
        } else if (key == "CurrentMap") {
            loadedCurrentMap = std::stoull(val);
        } else if (key == "CurrentOffset") {
            loadedOffset.SetBase16(const_cast<char*>(val.c_str()));
        } else if (key == "FinishedCount") {
            loadedFinishedCount = std::stoull(val);
        } else if (key == "Finished") {
            finishedMaps.insert(std::stoull(val));
            finishedRead++;
        } else if (key == "Target") {
            targetHashes.push_back(val);
        }
    }

    if (finishedRead != loadedFinishedCount) {
        std::cerr << "[RESUME] Warning: Expected " << loadedFinishedCount
                  << " finished maps but read " << finishedRead << "\n";
    }

    currentMapId = loadedCurrentMap;
    mode = (modeStr == "Random") ? ScanMode::RANDOM : ScanMode::SEQUENTIAL;
    nextSequentialHint = 0;
    while (nextSequentialHint < totalMaps &&
           finishedMaps.find(nextSequentialHint) != finishedMaps.end()) {
        nextSequentialHint++;
    }

    computeCurrentMap();
    if (!loadedOffset.IsZero() &&
        !loadedOffset.IsLower(&currentMapStart) &&
        !loadedOffset.IsGreater(&currentMapEnd)) {
        currentOffset.Set(&loadedOffset);
        mapFinished = false;
    }

    return true;
}

Int CooperativeMapScheduler::integerSqrt(const Int& n) {
    Int nCopy;
    nCopy.Set(const_cast<Int*>(&n));
    if (nCopy.IsZero() || nCopy.IsOne()) return nCopy;

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
            if (sq.IsGreater(&nCopy)) sum.SubOne();
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

void CooperativeMapScheduler::computeCurrentMap() {
    currentMapStart.Set(&startRange);
    if (currentMapId > 0) {
        Int offset;
        offset.SetInt32(0);
        offset.SetQWord(0, currentMapId);
        offset.Mult(&offset, &mapSize);
        currentMapStart.Add(&offset);
    }

    currentMapEnd.Set(&currentMapStart);
    currentMapEnd.Add(&mapSize);
    currentMapEnd.SubOne();

    if (currentMapEnd.IsGreater(&endRange)) {
        currentMapEnd.Set(&endRange);
    }

    currentOffset.Set(&currentMapStart);
    mapFinished = false;
}

void CooperativeMapScheduler::advanceToNextMap() {
    if (mode == ScanMode::SEQUENTIAL) {
        do {
            currentMapId++;
        } while (currentMapId < totalMaps &&
                 finishedMaps.find(currentMapId) != finishedMaps.end());
    } else {
        uint64_t remaining = totalMaps - finishedMaps.size();
        if (remaining == 0) {
            currentMapId = totalMaps;
            return;
        }

        if (remaining <= 1000) {
            std::vector<uint64_t> available;
            for (uint64_t i = 0; i < totalMaps; i++) {
                if (finishedMaps.find(i) == finishedMaps.end()) {
                    available.push_back(i);
                }
            }
            if (!available.empty()) {
                uint64_t idx = std::chrono::steady_clock::now().time_since_epoch().count() % available.size();
                currentMapId = available[idx];
            } else {
                currentMapId = totalMaps;
            }
        } else {
            uint64_t attempts = 0;
            bool found = false;
            while (attempts < 1000 && !found) {
                uint64_t candidate = std::chrono::steady_clock::now().time_since_epoch().count() % totalMaps;
                if (finishedMaps.find(candidate) == finishedMaps.end()) {
                    currentMapId = candidate;
                    found = true;
                }
                attempts++;
            }
            if (!found) {
                uint64_t start = std::chrono::steady_clock::now().time_since_epoch().count() % totalMaps;
                for (uint64_t i = 0; i < totalMaps; i++) {
                    uint64_t candidate = (start + i) % totalMaps;
                    if (finishedMaps.find(candidate) == finishedMaps.end()) {
                        currentMapId = candidate;
                        found = true;
                        break;
                    }
                }
                if (!found) currentMapId = totalMaps;
            }
        }
    }

    if (currentMapId < totalMaps) {
        computeCurrentMap();
    }
}
