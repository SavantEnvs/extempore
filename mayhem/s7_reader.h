// Shared by the s7 harnesses: one interpreter (re-created by fuzz_s7_read every N inputs), and a reader that
// turns a read error into #<eof> inside a Scheme `catch` so state never leaks
// from one input to the next.
#pragma once

#include <cstdint>
#include <cstdlib>
#include <string>

#include "s7.h"

namespace mayhem {

inline s7_scheme* g_sc = nullptr;
inline s7_pointer g_read_proc = nullptr;

inline void drop_char(s7_scheme*, uint8_t, s7_pointer) {}

inline void s7_reader_init() {
    g_sc = s7_init();
    s7_set_current_error_port(g_sc, s7_open_output_function(g_sc, drop_char));
    g_read_proc = s7_eval_c_string(
        g_sc, "(lambda (p) (catch #t (lambda () (read p)) (lambda args #<eof>)))");
    s7_gc_protect(g_sc, g_read_proc);
}

// Owns a string port over a NUL-terminated copy of the text.
class TextPort {
  public:
    explicit TextPort(const std::string& Text)
        : m_text(Text), m_port(s7_open_input_string(g_sc, m_text.c_str())),
          m_gc(s7_gc_protect(g_sc, m_port)) {}
    ~TextPort() {
        s7_gc_unprotect_at(g_sc, m_gc);
    }
    TextPort(const TextPort&) = delete;
    TextPort& operator=(const TextPort&) = delete;

    // Next datum, or the eof object at end of text or on a read error.
    s7_pointer next() {
        return s7_call(g_sc, g_read_proc, s7_cons(g_sc, m_port, s7_nil(g_sc)));
    }

  private:
    std::string m_text;
    s7_pointer m_port;
    s7_int m_gc;
};

inline bool is_eof(s7_pointer Obj) {
    return Obj == s7_eof_object(g_sc);
}

}  // namespace mayhem
