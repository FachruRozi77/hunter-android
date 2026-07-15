#ifndef MAPRANGE_H
#define MAPRANGE_H

#include "Int.h"
#include <cstdint>

struct MapRange {
    uint64_t id;
    Int start;
    Int end;
    bool finished;
    bool assigned;
    uint64_t checked;

    MapRange() : id(0), finished(false), assigned(false), checked(0) {}
};

#endif // MAPRANGE_H