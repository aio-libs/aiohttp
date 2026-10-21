/* llhttp's api.c references external wasm_on_* callbacks whenever __wasm__
   is defined; they are normally provided by JavaScript in llhttp's own
   WebAssembly bundle.  When llhttp is instead linked into a Python extension
   compiled with Emscripten (Pyodide) nothing provides those symbols, which
   makes the extension fail to load.  aiohttp installs its own callbacks via
   llhttp_init() and never uses the wasm_settings/llhttp_alloc() path, so
   no-op definitions are sufficient to satisfy the linker. */
#ifdef __wasm__

#include "llhttp.h"

int wasm_on_message_begin(llhttp_t *p) { return 0; }

int wasm_on_url(llhttp_t *p, const char *at, size_t length) { return 0; }

int wasm_on_status(llhttp_t *p, const char *at, size_t length) { return 0; }

int wasm_on_header_field(llhttp_t *p, const char *at, size_t length) {
  return 0;
}

int wasm_on_header_value(llhttp_t *p, const char *at, size_t length) {
  return 0;
}

int wasm_on_headers_complete(llhttp_t *p, int status_code, uint8_t upgrade,
                             int should_keep_alive) {
  return 0;
}

int wasm_on_body(llhttp_t *p, const char *at, size_t length) { return 0; }

int wasm_on_message_complete(llhttp_t *p) { return 0; }

#endif /* __wasm__ */
