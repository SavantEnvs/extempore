// Fuzzes the zone allocator (src/EXTZones.cpp) that backs every Extempore compiled-code allocation.
// The input is a sequence of operations (create / malloc / reset / copy / check) over a handful of
// zones. Oracle: allocations are 32-byte aligned, zeroed, report the footprint the allocator
// documents, stay inside their zone, and never disturb each other's contents.
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "EXTZones.h"

using namespace extemp::EXTZones;

namespace {

constexpr size_t MAX_ZONES = 4;
constexpr uint64_t BUDGET = 8u << 20;  // bytes requested per input

struct Alloc {
    uint8_t* ptr;
    uint64_t size;
    uint8_t pattern;
};

struct ZoneState {
    llvm_zone_t* zone = nullptr;
    std::vector<Alloc> allocs;
};

[[noreturn]] void broken(const char* What) {
    fprintf(stderr, "zone invariant violated: %s\n", What);
    abort();
}

uint64_t footprint(uint64_t Size) {
    return (Size + LLVM_ZONE_ALIGN + LLVM_ZONE_ALIGNPAD) & ~LLVM_ZONE_ALIGNPAD;
}

void check_contents(const ZoneState& Z) {
    for (const Alloc& a : Z.allocs) {
        if (llvm_zone_ptr_size(a.ptr) != footprint(a.size)) {
            broken("size header changed");
        }
        for (uint64_t i = 0; i < a.size; ++i) {
            if (a.ptr[i] != a.pattern) {
                broken("allocation contents were overwritten");
            }
        }
    }
}

class Bytes {
  public:
    Bytes(const uint8_t* Data, size_t Size) : m_data(Data), m_size(Size) {}
    bool empty() const {
        return m_pos >= m_size;
    }
    uint8_t u8() {
        return m_pos < m_size ? m_data[m_pos++] : 0;
    }

  private:
    const uint8_t* m_data;
    size_t m_size;
    size_t m_pos = 0;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    if (Size > 1024) {
        return -1;
    }
    Bytes in(Data, Size);
    ZoneState zones[MAX_ZONES];
    uint64_t spent = 0;
    uint8_t next_pattern = 1;

    while (!in.empty()) {
        const uint8_t op = in.u8() % 6;
        ZoneState& z = zones[in.u8() % MAX_ZONES];
        // sizes up to ~1 MB, biased small, so extension and rounding paths are both hit
        const uint64_t size = (uint64_t(in.u8()) << (in.u8() % 13)) + in.u8() % 40;
        switch (op) {
            case 0:  // (re)create the zone
                if (z.zone != nullptr) {
                    llvm_zone_destroy(z.zone);
                    z.zone = nullptr;
                    z.allocs.clear();
                }
                if (spent + size > BUDGET) {
                    break;
                }
                spent += size;
                z.zone = llvm_zone_create(size);
                break;
            case 1:
            case 2: {  // allocate and fill
                if (z.zone == nullptr || spent + size > BUDGET) {
                    break;
                }
                spent += size;
                auto* p = static_cast<uint8_t*>(llvm_zone_malloc(z.zone, size));
                if (p == nullptr || reinterpret_cast<uintptr_t>(p) % LLVM_ZONE_ALIGN != 0) {
                    broken("allocation is null or misaligned");
                }
                if (llvm_zone_ptr_size(p) != footprint(size)) {
                    broken("footprint header is wrong");
                }
                if (!llvm_ptr_in_zone(z.zone, p) || !llvm_ptr_in_zone(z.zone, p + size - (size ? 1 : 0))) {
                    broken("allocation is outside its zone");
                }
                for (uint64_t i = 0; i < footprint(size) - LLVM_ZONE_ALIGN; ++i) {
                    if (p[i] != 0) {
                        broken("fresh allocation is not zeroed");
                    }
                }
                const uint8_t pattern = next_pattern++ | 0x80;
                std::memset(p, pattern, size);
                z.allocs.push_back({p, size, pattern});
                break;
            }
            case 3:  // reset: earlier allocations are dead, the zone is reused from the start
                if (z.zone != nullptr) {
                    check_contents(z);
                    z.allocs.clear();
                    llvm_zone_reset(z.zone);
                }
                break;
            case 4: {  // copy one allocation over another
                if (z.allocs.empty()) {
                    break;
                }
                ZoneState& other = zones[in.u8() % MAX_ZONES];
                if (other.allocs.empty()) {
                    break;
                }
                Alloc& from = z.allocs[size % z.allocs.size()];
                Alloc& to = other.allocs[(size / 7) % other.allocs.size()];
                if (&from == &to) {
                    break;
                }
                const bool same = footprint(from.size) == footprint(to.size);
                const bool failed = llvm_zone_copy_ptr(from.ptr, to.ptr);
                // A copy that overruns `to` lands on the next allocation's size header; report it
                // here, next to the call, rather than at some later check.
                for (const Alloc& a : other.allocs) {
                    if (llvm_zone_ptr_size(a.ptr) != footprint(a.size)) {
                        broken("llvm_zone_copy_ptr overran the destination and changed a size header");
                    }
                }
                if (failed == same) {
                    broken("copy_ptr result disagrees with the allocation sizes");
                }
                if (!failed) {
                    to.pattern = from.pattern;
                    std::memset(to.ptr, from.pattern, to.size);
                }
                break;
            }
            default:
                check_contents(z);
                break;
        }
    }
    for (ZoneState& z : zones) {
        check_contents(z);
        if (z.zone != nullptr) {
            llvm_zone_destroy(z.zone);
        }
    }
    return 0;
}
