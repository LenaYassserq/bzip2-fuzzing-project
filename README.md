# bzip2 Fuzzing & Coverage Analysis
### SWE326 — Program Testing and Coverage Analysis | May 2026

---

##  Team Members

| Name |
|------|
| Lena Alqaissom |
| Reema Alqahtani  |
| Kawther |

---

## Project Overview

This project applies greybox fuzzing and source-based coverage analysis to **bzip2** — an open-source file compression program written in C (~7,000 lines). The goal is to discover bugs, measure code coverage, and analyze execution paths using industry-standard tools.

**Program:** `bzip2.c` — a single-file implementation containing both the command-line frontend and the full libbzip2 compression library.

---

##  Tools Used

| Tool | Purpose |
|------|---------|
| AFL++ v4.21c | Greybox fuzzing engine |
| afl-clang-fast (LLVM 20.1.8) | Instrumented compilation for fuzzing |
| LLVM opt | CFG and Call Graph generation |
| Graphviz dot | Graph rendering (PNG/PDF) |
| GCC + gcov | Coverage instrumentation |
| lcov + genhtml | Coverage report generation |
| ASAN (AddressSanitizer) | Crash analysis and confirmation |

---

##  Machine Specifications

| Component | Details |
|-----------|---------|
| OS | Ubuntu 24.04 LTS (ARM 64-bit) |
| VM | VirtualBox |
| RAM | 4,760 MB |
| AFL++ Version | 4.21c |
| Compiler | afl-clang-fast (LLVM 20.1.8) |

---

##  Repository Structure

```
bzip2-fuzzing-project/
│
├── report/
│   └── bzip2_final_report.pdf
│
├── graphs/
│   ├── callgraph.pdf
│   ├── uncompressStream_CFG.pdf
│   ├── BZ2_bzWrite_CFG.pdf
│   ├── uncompressStream_task4.pdf
│   ├── BZ2_bzWrite_task4.pdf
│   └── callgraph_task4.pdf
│
└── README.md
```

---

## Task 1 — CFG & Call Graph Generation

### Overview

We generated a **Call Graph** and two **Control Flow Graphs** using the LLVM toolchain.

- **Call Graph** — shows calling relationships across the entire program
- **CFG** — shows all possible execution paths inside a single function

### Commands

```bash
# Step 1: Compile to LLVM IR
clang -emit-llvm -S -g -D_FILE_OFFSET_BITS=64 bzip2.c -o bzip2.ll

# Step 2: Generate CFGs for all functions
opt --passes="dot-cfg" bzip2.ll -o /dev/null

# Step 3: Generate Call Graph
opt --passes="dot-callgraph" bzip2.ll -o /dev/null

# Step 4: Render to PNG/PDF
dot -Tpng .uncompressStream.dot -o uncompressStream_CFG.png
dot -Tpng .BZ2_bzWrite.dot -o BZ2_bzWrite_CFG.png
dot -Tpdf bzip2.ll.callgraph.dot -o callgraph.pdf
```

### Flag Reference

| Flag | Purpose |
|------|---------|
| `-emit-llvm` | Output LLVM IR instead of machine code |
| `-S` | Write IR in human-readable text format |
| `-g` | Embed debug info and line numbers |
| `-D_FILE_OFFSET_BITS=64` | Enable 64-bit file I/O — required by bzip2 |
| `--passes="dot-cfg"` | Generate CFG dot file per function |
| `--passes="dot-callgraph"` | Generate program-wide call graph |
| `-o /dev/null` | Discard IR output — we only need the dot files |

### Functions Analyzed

| Function | Location | Role |
|----------|----------|------|
| `uncompressStream()` | Line 5416 | Core decompression pipeline |
| `BZ2_bzWrite()` | Line 4366 | Library API for compression |

### Call Graph Architecture

```
main()
├── compress()
│   └── compressStream()
│       └── BZ2_bzWrite()        ← analyzed
└── uncompress()
    └── uncompressStream()       ← analyzed
        └── BZ2_bzRead()
```

---

## Task 2 — Fuzzing Campaigns

### Build

```bash
# Instrumented binary for fuzzing
afl-clang-fast -g -D_FILE_OFFSET_BITS=64 -o bzip2_afl bzip2.c

# Configure system for crash detection
echo core | sudo tee /proc/sys/kernel/core_pattern
```

### Flag Reference

| Flag | Purpose |
|------|---------|
| `afl-clang-fast` | AFL++ compiler — adds branch instrumentation |
| `-g` | Keep debug info for crash analysis |
| `-D_FILE_OFFSET_BITS=64` | Enable 64-bit file I/O |
| `echo core` | Write crash files to disk — required for AFL++ crash detection |

---

### Campaign 1 — Compression

```bash
afl-fuzz -i seeds_compress -o out_compress -t 500 -m 256 -- ./bzip2_afl -z @@
```

| Metric | Value |
|--------|-------|
| Run Time | 1 day, 6 hrs, 23 min |
| Total Executions | 309,000,000+ |
| Exec Speed | 5,487/sec |
| Corpus Count | 1,403 inputs |
| Saved Crashes | 0 |
| Saved Hangs | 2 |
| Map Density | 2.61% / 27.00% |
| Stability | 9.52% |

> **No crashes found.** Compression accepts any raw bytes as input — there is no structured format to violate, so any input is valid from bzip2's perspective.

---

### Campaign 2 — Decompression

```bash
afl-fuzz -i seeds_decompress -o out_decompress -t 500 -m 256 -- ./bzip2_afl -d -c @@
```

| Metric | Value |
|--------|-------|
| Run Time | 1 day, 6 hrs, 21 min |
| Total Executions | 166,000,000+ |
| Exec Speed | 753/sec |
| Corpus Count | 614 inputs |
| Saved Crashes | **14** |
| Saved Hangs | 118 |
| Map Density | 10.79% / 20.37% |
| Stability | 100% |

> **14 unique crashes found.** Decompression parses a strict binary format — malformed inputs trigger memory safety bugs deep in the parsing logic.

---

### Flag Reference

| Flag | Purpose |
|------|---------|
| `-i` | Input seed directory |
| `-o` | Output directory for queue, crashes, hangs |
| `-t 500` | Timeout = 500ms per test case |
| `-m 256` | Memory limit = 256MB per process |
| `@@` | Replaced by AFL++ with current test file path |
| `-z` | Compression mode |
| `-d` | Decompression mode |
| `-c` | Write output to stdout — prevents filling disk storage |

---

### Why Two Separate Campaigns?

| | Compression | Decompression |
|--|-------------|--------------|
| **Seed** | Any plain text file | Must be valid `.bz2` file |
| **Input requirement** | No format required | Strict `.bz2` format |
| **Target functions** | `compressStream()` → `BZ2_bzWrite()` | `uncompressStream()` → `BZ2_bzRead()` |

---

### Why is Decompression Slower?

```
Compression:   raw bytes → BWT → MTF → RLE → Huffman
               (simple, sequential — 5,487/sec)

Decompression: parse header → build Huffman tables
               → Huffman decode → MTF reverse
               → RLE reverse → BWT reverse → CRC verify
               (complex, multi-stage — 753/sec)
```

> Speed difference: **7x slower** — 5,487/sec vs 753/sec

---

### Artifact Structure

```
out_compress/default/
├── queue/        ← 1,403 unique test cases
├── crashes/      ← 0 crashes
├── hangs/        ← 2 timeout inputs
└── fuzzer_stats  ← full campaign statistics

out_decompress/default/
├── queue/        ← 614 unique test cases
├── crashes/      ← 14 unique crashing inputs
├── hangs/        ← 118 timeout inputs
└── fuzzer_stats  ← full campaign statistics
```

---

## Task 3 — Source-Based Coverage

### Build & Collection

```bash
# Step 1: Build coverage binary
gcc -g -fprofile-arcs -ftest-coverage \
    -D_FILE_OFFSET_BITS=64 \
    -o bzip2_cov bzip2.c -lgcov

# Step 2: Run all decompression queue inputs
for f in ~/out_decompress/default/queue/id:*; do
    ~/bzip2_cov -d -c "$f" 2>/dev/null
done

# Step 3: Run all compression queue inputs
for f in ~/out_compress/default/queue/id:*; do
    ~/bzip2_cov -z "$f" 2>/dev/null
done

# Step 4: Collect results
lcov --capture --directory ~ --output-file coverage.info

# Step 5: Generate HTML report
genhtml coverage.info --output-directory coverage_html
```

### Flag Reference

| Flag | Purpose |
|------|---------|
| `-fprofile-arcs` | Add execution counter at every branch |
| `-ftest-coverage` | Generate `.gcno` files mapping counters to lines |
| `-lgcov` | Link gcov library |
| `lcov --capture` | Collect all `.gcda` files into one `coverage.info` |
| `genhtml` | Render `coverage.info` as HTML report |

---

### Coverage Summary

| Campaign | Lines Covered | Line % | Functions Covered | Function % |
|----------|--------------|--------|------------------|------------|
| Decompression | 821 / 2747 | **29.9%** | 32 / 106 | **30.2%** |
| Compression | 1225 / 2747 | **44.6%** | 50 / 106 | **47.2%** |

---

### Key Function Coverage

| Function | Decompression | Compression | Reason |
|----------|--------------|-------------|--------|
| `uncompressStream()` line 5416 |  614 hits |  0 hits | Decompression-only function |
| `BZ2_bzWrite()` line 4366 |  0 hits | 8,052 hits | Compression-only function |

---

### Coverage Breakdown — uncompressStream()

| Code Path | Status | Hits | Reason if Uncovered |
|-----------|--------|------|---------------------|
| Entry block + initialization |  Covered | 614 | Called once per test case |
| `BZ2_bzReadOpen()` call |  Covered | 4,927 | Multiple streams per file |
| Inner read loop |  Covered | 32,033 | ~6 iterations per stream |
| `BZ2_bzRead()` + `fwrite()` |  Covered | 27,125 | Main decompression path |
| `BZ2_bzReadClose()` | Covered | 4,315 | End of each stream |
| `trycat` fallback path |  Not covered | 0 | Requires `-f` flag + non-bzip2 file |
| `outOfMemory()` handler |  Not covered | 0 | Requires `malloc()` failure |
| `configError()` handler |  Not covered | 0 | Requires corrupt library config |

---

### Coverage Breakdown — BZ2_bzWrite()

| Code Path | Status | Hits | Reason if Uncovered |
|-----------|--------|------|---------------------|
| Entry + validation | Covered | 8,052 | Normal execution path |
| Compression loop |  Covered | 8,052 | Called for every input chunk |
| `BZ2_bzCompress()` call | Covered | 8,052 | Core compression step |
| `fwrite()` output |  Covered | 8,052 | Flush compressed output |
| `BZ_PARAM_ERROR` path |  Not covered | 0 | Requires `NULL` pointer or negative length |
| `BZ_SEQUENCE_ERROR` path | Not covered | 0 | Requires wrong file open mode |
| `BZ_IO_ERROR` path |  Not covered | 0 | Requires real disk failure |

---

### Why is Coverage Low?

```
Reason 1: Each campaign covers only its own code path
          → ~50% of the program always shows zero hits

Reason 2: Error paths require hardware conditions
          → Disk full, memory exhaustion, I/O failures

Reason 3: Utility functions never called during fuzzing
          → usage(), license(), testf(), signal handlers

Reason 4: Paths require specific command-line flags
          → forceOverwrite path needs -f flag
          → AFL++ only mutates file content, not flags
```

---

## Task 4 — Coverage Mapping & Analysis

### Methodology

Coverage data from Task 3 was mapped onto the CFG diagrams from Task 1.

| Color | Meaning |
|-------|---------|
| Green | CFG node was reached by the fuzzer |
|  Red | CFG node was never reached |
| White | Function was never called (Call Graph) |

---

### uncompressStream() — Decompression Campaign

| Region | Coverage | Notes |
|--------|----------|-------|
| Entry + error checks | Covered | First block executed 614 times |
| `BZ2_bzReadOpen()` block | Covered | 4,927 stream opens |
| Inner read loop | Covered | 32,033 loop iterations |
| `fwrite()` block | Covered | 26,513 writes |
| `BZ2_bzReadClose()` | Covered | 4,315 stream closes |
| `trycat` fallback |  Not covered | Needs `-f` flag |
| `outOfMemory()` path | Not covered | Needs `malloc()` failure |
| `configError()` path |  Not covered | Needs corrupt config |

---

### BZ2_bzWrite() — Compression Campaign

| Region | Coverage | Notes |
|--------|----------|-------|
| Entry + validation |  Covered | 8,052 calls |
| Compression loop | Covered | 8,052 iterations |
| `fwrite()` output |  Covered | 8,052 flushes |
| `BZ_PARAM_ERROR` |  Not covered | AFL++ always provides valid parameters |
| `BZ_SEQUENCE_ERROR` | Not covered | File always opened correctly |
| `BZ_IO_ERROR` |  Not covered | No disk errors in VM |

---

### Source Coverage vs Graph Coverage

| | Source Coverage (lcov) | Graph Coverage (CFG) |
|--|----------------------|---------------------|
| **Measures** | Which lines executed | Which nodes/edges visited |
| **Output** | Percentage + line counts | Visual color-coded diagram |
| **Best for** | Quantifying coverage | Understanding missed paths |
| **Our results** | 29.9% / 44.6% | Annotated CFG diagrams |

---

##  Bug Found

### Heap Buffer Underflow — `BZ2_decompress()` Line 3369

| Property | Details |
|----------|---------|
| **Type** | Heap Buffer Underflow |
| **Classification** | CWE-125: Out-of-bounds Read |
| **Function** | `BZ2_decompress()` |
| **Line** | 3369 |
| **Crashes Found** | 14 unique inputs |
| **Confirmed by** | ASAN (AddressSanitizer) |

---

### Vulnerable Code

```c
s->tt[s->cftab[uc]] |= (i << 8);
```

**Root Cause:**
The code uses a value from the compressed file (`uc`) as an array index into `s->cftab[]` without validating that the result is non-negative. AFL++ crafted inputs that make `s->cftab[uc]` return a negative value, causing the program to read memory before the start of the `s->tt` array (3.6 million elements).

---

### Call Stack

```
#5  main()              → line 6948
#4  uncompress()        → line 6436
#3  uncompressStream()  → line 5444
#2  BZ2_bzRead()        → line 4601
#1  BZ2_bzDecompress()  → line 4244
#0  BZ2_decompress()    → line 3369  ← CRASH
```

---

### ASAN Output

```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4
8 bytes BELOW the region start
at BZ2_decompress() bzip2.c:3369
```

---

### Fix

```c
// Add before line 3369:
if (s->cftab[uc] < 0 || s->cftab[uc] >= nblock) {
    return BZ_DATA_ERROR;
}
// Original line:
s->tt[s->cftab[uc]] |= (i << 8);
```

---

##  Seeds Experiment

Two one-hour decompression campaigns to evaluate seed selection impact:

| Metric | Single Seed | Multi Seeds |
|--------|------------|-------------|
| Run Time | 1 hr 17 min | 1 hr 18 min |
| Corpus Count | 492 | 430 |
| Saved Crashes | 2 | 2 |
| New Edges | 116 (23.58%) | 109 (25.35%) |
| Map Density | 9.93% | 8.80% |

> **Conclusion:** Diverse seeds achieved higher new edge coverage (25.35% vs 23.58%). The advantage becomes more significant over longer campaigns.

---

##  Key Observations

- Compression found **zero crashes** — no structured format to violate
- Decompression found **14 crashes** — strict binary format creates exploitable parsing paths  
- Decompression is **7x slower** — complex multi-stage parsing vs sequential compression
- Coverage gap of **~15%** between campaigns — due to separated code paths
- All 14 crashes share the **same root cause** — one missing bounds check at line 3369
- Error handling paths remain **uncovered** — require hardware failures AFL++ cannot simulate

---

*SWE326 — May 2026*
