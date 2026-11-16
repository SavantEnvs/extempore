// Fuzzes Extempore's OSC receive path (src/OSC.cpp osc_dispatch_packet): oscpp packet/bundle
// parsing plus the Scheme call text built from each message. First input byte picks the mode
// (bit0: include sender address, bit1: native callback instead of the Scheme path).
//
// The real src/OSC.cpp is compiled into this TU. The build links with --gc-sections, so the
// interpreter-side functions it also defines (never called here) drop out unresolved.
//
// Injection oracle: the call text queued for the interpreter must read back as exactly one
// datum, `(fname time "address" [... netaddr] args...)`, whose arguments are only numbers,
// strings and `(list ...)` of those. Anything else means packet bytes reached the interpreter
// as source.
#include "../src/OSC.cpp"

#include <cstdlib>
#include <string>
#include <vector>

#include "s7_reader.h"

namespace extemp {

static std::vector<std::string>* g_forms = nullptr;

void SchemeProcess::createSchemeTask(void* Arg, const std::string&, SchemeTask::Type) {
    std::string* form = static_cast<std::string*>(Arg);
    if (g_forms != nullptr) {
        g_forms->push_back(std::move(*form));
    }
    delete form;
}

}  // namespace extemp

namespace {

[[noreturn]] void injection(const char* Why, const std::string& Form) {
    fprintf(stderr, "OSC call text is not a plain call (%s): %s\n", Why, Form.c_str());
    abort();
}

bool plain_argument(s7_pointer Arg) {
    if (s7_is_number(Arg) || s7_is_string(Arg)) {
        return true;
    }
    if (!s7_is_pair(Arg) || !s7_is_symbol(s7_car(Arg)) ||
        std::string(s7_symbol_name(s7_car(Arg))) != "list") {
        return false;
    }
    for (s7_pointer rest = s7_cdr(Arg); s7_is_pair(rest); rest = s7_cdr(rest)) {
        if (!plain_argument(s7_car(rest))) {
            return false;
        }
    }
    return true;
}

void check_call_text(const std::string& Form, const std::string& Fname, bool WithNetaddr) {
    mayhem::TextPort port(Form);
    s7_pointer call = port.next();
    if (mayhem::is_eof(call)) {
        injection("unreadable", Form);
    }
    if (!mayhem::is_eof(port.next())) {
        injection("extra datum after the call", Form);
    }
    if (!s7_is_pair(call) || !s7_is_symbol(s7_car(call)) ||
        Fname != s7_symbol_name(s7_car(call))) {
        injection("head is not the callback", Form);
    }
    s7_pointer rest = s7_cdr(call);
    // time, address, then (netaddr string, port) when requested
    const int fixed = WithNetaddr ? 4 : 2;
    for (int i = 0; i < fixed; ++i, rest = s7_cdr(rest)) {
        if (!s7_is_pair(rest)) {
            injection("short header", Form);
        }
        s7_pointer item = s7_car(rest);
        const bool want_string = i == 1 || (WithNetaddr && i == 2);
        if (want_string ? !s7_is_string(item) : !s7_is_number(item)) {
            injection("bad header field", Form);
        }
    }
    for (; s7_is_pair(rest); rest = s7_cdr(rest)) {
        if (!plain_argument(s7_car(rest))) {
            injection("argument is not a plain value", Form);
        }
    }
    if (!s7_is_null(mayhem::g_sc, rest)) {
        injection("improper call", Form);
    }
}

volatile uint64_t g_sink = 0;

int native_callback(char* Address, char* TypeTags, char* Args, int ArgBytes) {
    uint64_t sum = strlen(Address) + strlen(TypeTags);
    for (int i = 0; i < ArgBytes; ++i) {
        sum += static_cast<uint8_t>(Args[i]);
    }
    g_sink = sum;
    return 0;
}

alignas(extemp::SchemeProcess) unsigned char g_proc_storage[sizeof(extemp::SchemeProcess)];

}  // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    mayhem::s7_reader_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    using namespace extemp;
    if (Size < 1 || Size > 2048) {
        return -1;
    }
    const bool netaddr = Data[0] & 1;
    const bool native = Data[0] & 2;
    std::vector<char> packet(Data + 1, Data + Size);  // exact size: ASan sees any over-read

    static OSC osc;
    osc.fname = "osc-callback";
    osc.setNativeOSC(native ? native_callback : nullptr);

    std::vector<std::string> forms;
    g_forms = &forms;
    osc_dispatch_packet(&osc, reinterpret_cast<SchemeProcess*>(g_proc_storage), packet.data(),
                        static_cast<int>(packet.size()), netaddr, "127.0.0.1", 9000);
    g_forms = nullptr;

    for (const std::string& form : forms) {
        check_call_text(form, osc.fname, netaddr);
    }
    return 0;
}
