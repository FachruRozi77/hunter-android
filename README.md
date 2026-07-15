 # BTC Puzzle Hunter v4.0 — Map Scheduler Edition

> **High-performance Bitcoin private key search for Android/ARM64 with deterministic coverage, precise resume, and zero overlap.**

---

## What This Is

A CPU-optimized **secp256k1** keyspace scanner designed for the [Bitcoin Puzzle Transaction](https://privatekeys.pw/puzzles/bitcoin-puzzle-tx) challenges. It searches a defined hexadecimal range for private keys whose compressed public keys hash to a target **Hash160**, using Jean Luc Pons' batch-modular-inversion ECC engine and OpenSSL EVP hashing.

**v4.0 introduces a Map Scheduler** that replaces chaotic random key generation with deterministic, resumable, non-overlapping map-based coverage.

---

## Why v4.0 Is Different

| Problem (v3.x and earlier) | v4.0 Solution |
|---|---|
| Random keys → **no guarantee** of full coverage | **Map Scheduler** divides range into √N-sized blocks; every key belongs to exactly one map |
| Overlap between threads → **wasted work** | Maps are **atomically assigned**; no two threads ever scan the same block |
| Crash = **total progress loss** | **Progress.dat** saves completed-map bitmap + current offset every 60s; resume to the exact key |
| "Checked 50 trillion keys" = meaningless progress | **Map progress %** tells you exactly how much of the keyspace is exhausted |
| Multiple SHA256/RIPEMD160 implementations | **Single `Hash160` class** via OpenSSL EVP — one code path, one place to optimize |

---

## Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   MapScheduler  │────▶│   Worker Thread │────▶│  Secp256K1 ECC  │
│  (owns ranges)  │     │ (sequential scan│     │ (batch inversion│
│                 │     │  inside one map)│     │  + Jacobian→Affine)
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                       │
         ▼                       ▼
   Progress.dat              Hash160
   (bitmap + offset)         (EVP_sha256 → EVP_ripemd160)
```

**Key design rule:** The scheduler owns the maps. Workers never calculate ranges. ECC and hashing code is untouched from the proven Jean Luc Pons implementation.

---

## Building

### Prerequisites (Termux)
```bash
pkg install clang++ openssl libopenssl-dev make
```

### Compile
```bash
make              # Native build, auto-detects your ARM64 CPU
make release      # Stripped release binary
make debug        # Debug symbols, no optimization
```

The Makefile uses `-mcpu=native` when building on-device so the compiler tunes to your exact chip (Cortex-A76, X2, X3, Apple M-series, etc.). Cross-compiles fall back to generic ARMv8-A.

### Install
```bash
make install      # Copies to $PREFIX/bin/
```

---

## Usage

### Basic Sequential Scan
```bash
./btc-puzzle-hunter \
  -r 400000000000000000:7fffffffffffffffff \
  -h160 f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8 \
  -maxtemp 55
```

### Random Map Mode
```bash
./btc-puzzle-hunter \
  -r 20000000000000000:3ffffffffffffffff \
  -h160 739437bb8dd3b9e8c6f0e2f3b8a1c5d7e9f2b4a6 \
  -random \
  -maxtemp 60
```

**Random mode is not random keys.** It randomly selects unfinished maps, then scans each map **sequentially to completion**. This preserves deterministic coverage while avoiding predictable patterns.

### Multiple Targets
```bash
./btc-puzzle-hunter \
  -r 20000000000000000:3ffffffffffffffff \
  -h160 abc... \
  -h160 def... \
  -h160 123... \
  -maxtemp 55 \
  -stat 10000
```

### CLI Options

| Flag | Description | Default |
|---|---|---|
| `-r START:END` | Search range in hex (inclusive) | **Required** |
| `-h160 HASH` | Target Hash160 (40 hex chars). Repeatable. | **Required** |
| `-maxtemp N` | Pause when CPU temp exceeds N°C | 85 |
| `-stat MS` | Status refresh interval in milliseconds | 30000 |
| `-random` | Random map selection mode | Sequential |
| `-h, --help` | Show help | — |

---

## The Map Scheduler

### How Maps Are Built

```
TotalElements = End - Start + 1
MapSize       = floor(sqrt(TotalElements))
MapCount      = ceil(TotalElements / MapSize)

Map i:
  Start = StartRange + i × MapSize
  End   = min(StartRange + (i+1) × MapSize - 1, EndRange)
```

**Example:** Puzzle 71 range `400000000000000000` to `7fffffffffffffffff` (~2⁶⁰ keys)
- ~1,073,741,824 maps
- Each map ≈ 1,073,741,823 keys (~1 billion)
- 32-bit map IDs, 64-bit offsets inside maps

### Worker Loop

```
while running:
    map = scheduler.getNextMap()        // atomic, mutex-protected
    for key = map.start → map.end:
        fill batch with key, key+1, ...
        ComputePublicKeyBatch()
        Hash160::computeBatch()
        bloom filter → candidate check → target compare
    scheduler.finishMap(map.id)         // marks in bitmap
```

**No `generateRandomIntInRange()`.** No duplicate work. No gaps.

---

## Resume & Progress

### Auto-Save
Every **60 seconds** and on graceful shutdown, `Progress.dat` is written:

```ini
Version=2
Mode=Sequential
StartRange=400000000000000000
EndRange=7fffffffffffffffff
MapCount=1073741824
Interval=1073741823
CompletedMaps=15432
CurrentMap=15433
CurrentOffset=400000000000000000
Bitmap=1111111111111111111111111111111111111111111111111111111111111111...
TargetCount=1
Target=f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8
```

### Resume Flow
1. App starts → detects `Progress.dat`
2. Validates range and target hashes match current command
3. If valid: restores completed-map bitmap, current map, and offset
4. If invalid/mismatched: prompts to continue anyway or start fresh

### Manual Recovery
If a map was in-flight during a crash, the **worst-case loss is one partial map** (~1 billion keys). On restart, that map is reassigned and rescanned from its start. All completed maps are permanently recorded in the bitmap.

---

## Display & Statistics

```
╔══════════════════════════════════════════════════════════════╗
║         BTC PUZZLE HUNTER v4.0 - MAP SCHEDULER               ║
╠══════════════════════════════════════════════════════════════╣
║ Threads:     8 / 8 active                                    ║
║ Mode:        Sequential                                        ║
╠══════════════════════════════════════════════════════════════╣
║ MAP PROGRESS                                                   ║
║ Maps:        15,432 / 1,073,741,824                            ║
║ Remaining:   1,073,726,392                                     ║
║ Progress:    0.00%                                             ║
╠══════════════════════════════════════════════════════════════╣
║ KEY PROGRESS                                                   ║
║ Keys/sec:    2,847,291                                         ║
║ Total:       16,589,234,112                                    ║
║ Elapsed:     01:37:12                                          ║
║ Candidates:  0                                                 ║
║ Matches:     0                                                 ║
╠══════════════════════════════════════════════════════════════╣
║ SYSTEM                                                         ║
║ Memory:      1,247/7,744 MB                                    ║
║ Est. Remain: 3842:17:33                                        ║
║ Refresh:     30000 ms                                          ║
╚══════════════════════════════════════════════════════════════╝
```

| Field | Meaning |
|---|---|
| **Maps** | Completed / Total. This is your **real progress metric**. |
| **Progress %** | `completed / total × 100`. No guesswork. |
| **Est. Remain** | Based on maps-per-second, not keys. Accurate regardless of batch size. |
| **Keys/sec** | Raw throughput for performance tuning. |
| **Candidates** | Bloom filter positives (false + true). Written to `candidates.txt`. |
| **Matches** | Verified Hash160 hits. Written to `found.txt`. |

---

## Files

| File | Purpose |
|---|---|
| `btc-puzzle-hunter` | Binary |
| `Progress.dat` | Resume state (bitmap + offset). **Do not delete if resuming.** |
| `found.txt` | Verified private keys with their Hash160. Appended, never overwritten. |
| `candidates.txt` | Bloom filter hits for manual inspection. |
| `candidates.txt` | Bloom filter hits for manual inspection. |

---

## Performance Tips

### 1. Thermal Headroom
Android phones throttle aggressively. Use `-maxtemp` to pause before thermal throttling kicks in. Typical values:
- **Passive cooling:** 55–65°C
- **Active cooler / desktop ARM:** 75–85°C

### 2. CPU Affinity
The Makefile includes a `run` target that pins to big cores:
```bash
make run    # taskset -c 4-7 ./btc-puzzle-hunter
```
Adjust core numbers for your device (`/proc/cpuinfo` or `lscpu`).

### 3. Batch Size Tuning
`POINTS_BATCH_SIZE` (default 4096) is the sweet spot for L1 cache on most ARM64 cores. Increase if you have larger caches; decrease if memory-constrained.

### 4. Multiple Targets
Each additional `-h160` adds 20 bytes to the Bloom filter. The filter is 16MB with 12 hashes — room for thousands of targets with <1% false positive rate.

---

## Technical Details

### ECC Engine
- **Jean Luc Pons' Secp256K1** with 256-entry windowed-comb generator table
- **Batch modular inversion** via `IntGroup::ModInv()` — one `modinv` per 4096 keys instead of 4096
- Jacobian coordinates throughout; single batch affine conversion at the end

### Hashing
- **Single `Hash160` class** using OpenSSL EVP
- `EVP_sha256()` → 32 bytes → `EVP_ripemd160()` → 20 bytes
- Context reuse across the entire batch (no init/free per key)

### Thread Safety
- `MapScheduler` mutex: held only during map assignment/finish (microseconds)
- `BloomFilter`: lock-free atomics on byte array
- `g_foundMutex`: held only on actual match (rare)
- Statistics: relaxed atomics, batched per-thread to minimize cache coherency traffic

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `Cannot open found.txt` | Check write permissions in current directory |
| `Progress.dat` resume fails | Verify range and `-h160` values match exactly |
| Very low keys/sec | Check thermal throttling (`-maxtemp` too high); try `taskset` |
| Out of memory | Reduce `POINTS_BATCH_SIZE` in source and recompile |
| "Unknown option" | Flags are case-sensitive; use `-h160` not `-H160` |

---

## License

The secp256k1 arithmetic core (`Int.*`, `IntGroup.*`, `SECP256K1.*`, `Point.*`) is Copyright (c) 2020 Jean Luc Pons, licensed under GPLv3.

All scheduler, progress, and build system modifications are provided under the same GPLv3 license.

---

## Version History

| Version | Change |
|---|---|
| v3.0 | Initial ARM64 release with batch inversion, thread affinity, thermal management |
| **v4.0** | **Map Scheduler, deterministic coverage, resume-to-key, unified Hash160, random-map mode, map-based statistics** |

---

**Build it. Run it. Find the key. Resume when life interrupts.**
