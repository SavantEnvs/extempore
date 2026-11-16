#!/usr/bin/env bash
#
# mayhem/build.sh -- build the Extempore fuzz harnesses and the unit-test oracle.
#
# The whole Extempore tree needs an LLVM 22 FetchContent build (hours, network), so the
# harnesses cover self-contained components instead: the OSC packet parser and Scheme-call
# builder (src/OSC.cpp), the s7 Scheme reader (src/s7.c) and the zone allocator
# (src/EXTZones.cpp). Each is compiled from the real upstream source with the sanitizers on.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OBJ=build/mayhem            # /build is gitignored upstream; everything here is recreated each run
rm -rf "$OBJ"
mkdir -p "$OBJ/fuzz" "$OBJ/tests"

INC="-Iinclude -Isrc -Isrc/oscpp/include -Imayhem"
# -fsanitize=fuzzer-no-link on the fuzzed code is what gives libFuzzer its edge counters.
# --gc-sections needs the per-function sections; it also drops the unresolved interpreter glue
# in src/OSC.cpp that the OSC harness never calls.
CXXF="-std=c++20 -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -ffunction-sections -fdata-sections $INC"

# 1) the fuzzed library code, sanitized.
#    s7.c reads 8-byte values at odd offsets while initialising its symbol table (s7.c:4325); that
#    is benign on x86 and fires on every input, so only the alignment check is relaxed for this file.
$CC -std=c17 -O1 $SANITIZER_FLAGS -fno-sanitize=alignment $DEBUG_FLAGS -fsanitize=fuzzer-no-link \
    -ffunction-sections -fdata-sections -w \
    -DHAVE_COMPLEX_NUMBERS=0 -DWITH_SYSTEM_EXTRAS=0 -DWITH_C_LOADER=0 -DWITH_GMP=0 \
    -Iinclude -c src/s7.c -o "$OBJ/fuzz/s7.o" &
pids=($!)
$CXX $CXXF -c src/EXTZones.cpp -o "$OBJ/fuzz/EXTZones.o" &
pids+=($!)
$CXX $CXXF -c src/EXTThread.cpp -o "$OBJ/fuzz/EXTThread.o" &
pids+=($!)
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OBJ/fuzz/lsan_off.o" &
pids+=($!)
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/fuzz/standalone_main.o" &
pids+=($!)
for h in fuzz_osc_packet fuzz_s7_read fuzz_zones; do
  $CXX $CXXF -c "mayhem/$h.cpp" -o "$OBJ/fuzz/$h.o" &
  pids+=($!)
done
for pid in "${pids[@]}"; do wait "$pid"; done

# 2) one fuzzer and one standalone reproducer per harness.
LINK="$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fuse-ld=lld -Wl,--gc-sections"
LIBS="-ldl -lm -lpthread"
declare -A DEPS=(
  [fuzz_osc_packet]="$OBJ/fuzz/s7.o $OBJ/fuzz/EXTThread.o"
  [fuzz_s7_read]="$OBJ/fuzz/s7.o"
  [fuzz_zones]="$OBJ/fuzz/EXTZones.o"
)
for h in "${!DEPS[@]}"; do
  $LINK $LIB_FUZZING_ENGINE "$OBJ/fuzz/$h.o" ${DEPS[$h]} "$OBJ/fuzz/lsan_off.o" $LIBS -o "$SRC/$h"
  $LINK -fsanitize=fuzzer-no-link "$OBJ/fuzz/standalone_main.o" "$OBJ/fuzz/$h.o" ${DEPS[$h]} \
      "$OBJ/fuzz/lsan_off.o" $LIBS -o "$SRC/$h-standalone"
done

# 3) the oracle: upstream's whole tests/cpp-unit/ gtest binary (the 7 files and 2 sources its
#    CMakeLists.txt lists), built with normal flags (no sanitizers) from the same sources.
$CXX -std=c++20 -O2 $COVERAGE_FLAGS -Iinclude -Isrc \
    tests/cpp-unit/{univ,sharedir,netutil,osc,zones,scheduler,ir_preamble}_test.cpp \
    src/EXTThread.cpp src/EXTZones.cpp \
    -lgtest -lgtest_main -lpthread -o "$OBJ/tests/extempore_cpp_unit"
