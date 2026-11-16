// Fuzzes the s7 Scheme reader (src/s7.c), which parses every form Extempore evaluates:
// REPL and socket input, OSC-built calls, and loaded source files.
#include <cstdint>
#include <cstdlib>
#include <string>

#include "s7_reader.h"

// s7 never frees a non-gensym symbol, so every distinct symbol or keyword an input reads stays
// interned for the life of the interpreter. A fresh interpreter every N inputs bounds that growth;
// the one-off s7_init cost is amortised over the N inputs.
constexpr unsigned REINIT_EVERY = 2000;
unsigned g_inputs = 0;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    mayhem::s7_reader_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    if (Size > 4096) {
        return -1;
    }
    if (++g_inputs % REINIT_EVERY == 0) {
        s7_free(mayhem::g_sc);
        mayhem::s7_reader_init();
    }
    mayhem::TextPort port(std::string(reinterpret_cast<const char*>(Data), Size));
    for (int i = 0; i < 64; ++i) {
        s7_pointer obj = port.next();
        if (mayhem::is_eof(obj)) {
            break;
        }
        free(s7_object_to_c_string(mayhem::g_sc, obj));
    }
    return 0;
}
