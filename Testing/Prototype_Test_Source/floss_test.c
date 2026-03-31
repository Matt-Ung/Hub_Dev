#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Simple XOR decoder (runtime-decoded string)
void xor_decode(char *out, const uint8_t *enc, size_t n, uint8_t key) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)(enc[i] ^ key);
    }
    out[n] = '\0';
}

int main(void) {
    // 1) Static string (easy baseline)
    const char *static_str = "STATIC: https://example.com/api/v1/ping";

    // 2) Stack string (manually built on stack)
    char stack_str[] = {
        'S','T','A','C','K',':',' ',
        'c','m','d','.','e','x','e',' ',
        '/','c',' ','w','h','o','a','m','i',
        '\0'
    };

    // 3) XOR-encoded string (decoded at runtime)
    // Original plaintext: "DECODED: kernel32.dll"
    uint8_t enc[] = {
        0x11,0x10,0x16,0x1a,0x11,0x10,0x11,0x6f,0x75,0x3e,
        0x30,0x27,0x3b,0x30,0x39,0x66,0x67,0x7b,0x31,0x39,0x39
    };
    char decoded[sizeof(enc) + 1];
    xor_decode(decoded, enc, sizeof(enc), 0x55);

    // Print so the compiler keeps things around
    puts(static_str);
    puts(stack_str);
    puts(decoded);

    return 0;
}