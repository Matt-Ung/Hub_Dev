/*
 * File:       multilayer_encode_test.c
 * Purpose:    Multi-layer string encoding sample.  Strings are protected
 *             by two sequential transformations: a byte-rotate (ROL) step
 *             followed by an XOR step, each with a different key.  The
 *             encoded payloads contain C2-style URLs, file paths, and
 *             shell commands that a reverse engineer must recover.
 *
 * Difficulty: HARD
 *
 * Techniques:
 *   - Two-layer encoding: ROL(n) then XOR(key)
 *   - Encoded C2-style URLs, registry paths, shell commands
 *   - Stack-based decode buffers (not heap)
 *   - Magic-header validation on the encoded blob
 *   - Per-entry metadata (offset, length, layer keys)
 *
 * Why it matters for testing:
 *   Single-byte XOR is the simplest encoding pattern and is well-handled
 *   by FLOSS.  This sample tests whether the pipeline can handle a
 *   slightly more complex scheme where FLOSS may partially recover
 *   strings (after XOR) but the ROL layer may cause garbled output.
 *   The analysis agents should:
 *     (a) identify the two-stage decode routine via Ghidra
 *     (b) use FLOSS to attempt string recovery
 *     (c) flag the C2-style indicators for YARA / capa matching
 *
 *   This also tests whether YARA rules fire on the decoded content
 *   (they won't unless the binary is run or strings are extracted).
 *
 * Expected analysis signals:
 *   - Ghidra decompilation shows the two-pass decode loop
 *   - FLOSS may recover partial or full strings depending on emulation
 *   - Recovered strings include:
 *       "https://c2.example.net/beacon/checkin"
 *       "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
 *       "cmd.exe /c schtasks /create /sc minute /mo 15 /tn Updater"
 *   - capa flags: "encode data", "decode data via XOR",
 *     "reference command shell", "reference registry"
 *   - YARA rules may match on C2 URL patterns or registry key patterns
 *     if string extraction succeeds
 *
 * Recommended MCP servers / tools:
 *   - flareflossmcp   : primary; stack-string and decoded-string recovery
 *   - stringmcp       : cleartext format strings, partial blob fragments
 *   - ghidramcp       : decompilation of decode_entry, the ROL/XOR loops
 *   - CapaMCP         : behavioral rules for encoding, shell, registry
 *   - yaramcp         : rule matching on extracted string indicators
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------
 * Encoding parameters.
 * Layer 1: rotate each byte left by ROL_BITS.
 * Layer 2: XOR each byte with XOR_KEY.
 * Decoding is the reverse: XOR first, then rotate right.
 * --------------------------------------------------------------- */
#define ROL_BITS  3
#define XOR_KEY   0x7E

/* ---------------------------------------------------------------
 * Blob header magic.
 * The decoder checks this value before proceeding, which gives
 * Ghidra a recognizable constant to anchor analysis on.
 * --------------------------------------------------------------- */
#define BLOB_MAGIC 0xCAFED00Du

/* ---------------------------------------------------------------
 * EncodedEntry -- one encoded string with its metadata.
 * The metadata is stored in cleartext so that a reverse engineer
 * can locate the entries and understand the layout before tackling
 * the decode routine.
 * --------------------------------------------------------------- */
typedef struct {
    uint16_t offset;    /* byte offset into the encoded payload */
    uint16_t length;    /* encoded length (no null terminator) */
    uint8_t  rol_bits;  /* layer-1 rotation amount */
    uint8_t  xor_key;   /* layer-2 XOR key */
    uint16_t _pad;      /* alignment padding */
} EncodedEntry;

typedef struct {
    uint32_t     magic;
    uint16_t     entry_count;
    uint16_t     _reserved;
    EncodedEntry entries[4];
    uint8_t      payload[256];
} EncodedBlob;

/* ---------------------------------------------------------------
 * rol8 / ror8 -- single-byte bitwise rotation helpers.
 * These are small enough to be inlined, so the decompiler may
 * show them as inline shift/or expressions rather than function
 * calls.
 * --------------------------------------------------------------- */
static uint8_t rol8(uint8_t v, int n)
{
    n &= 7;
    return (uint8_t)((v << n) | (v >> (8 - n)));
}

static uint8_t ror8(uint8_t v, int n)
{
    n &= 7;
    return (uint8_t)((v >> n) | (v << (8 - n)));
}

/* ---------------------------------------------------------------
 * encode_string -- encode a plaintext string in-place into the
 * blob payload.  Used only during compile-time blob construction
 * (see init_blob).
 * --------------------------------------------------------------- */
static void encode_string(uint8_t *out, const char *plain, int len,
                          int rol, uint8_t xor)
{
    for (int i = 0; i < len; i++) {
        uint8_t b = (uint8_t)plain[i];
        b = rol8(b, rol);     /* layer 1: rotate left */
        b = b ^ xor;          /* layer 2: XOR */
        out[i] = b;
    }
}

/* ---------------------------------------------------------------
 * decode_entry -- runtime decode of one encoded string.
 * Reverses the two layers: XOR first, then rotate right.
 * This is the primary target for FLOSS emulation.
 * --------------------------------------------------------------- */
static void decode_entry(char *out, const uint8_t *payload,
                         const EncodedEntry *ent)
{
    for (uint16_t i = 0; i < ent->length; i++) {
        uint8_t b = payload[ent->offset + i];
        b = b ^ ent->xor_key;           /* undo layer 2 */
        b = ror8(b, ent->rol_bits);      /* undo layer 1 */
        out[i] = (char)b;
    }
    out[ent->length] = '\0';
}

/* ---------------------------------------------------------------
 * init_blob -- builds the encoded blob at runtime.
 * In a real malware sample these bytes would be hardcoded in the
 * binary.  Here we encode at startup so the source remains
 * readable and the test is reproducible.
 *
 * Plaintext payloads:
 *   [0] "https://c2.example.net/beacon/checkin"
 *   [1] "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
 *   [2] "cmd.exe /c schtasks /create /sc minute /mo 15 /tn Updater"
 *   [3] "AppData\\Local\\Temp\\svchost_update.dat"
 * --------------------------------------------------------------- */
static void init_blob(EncodedBlob *blob)
{
    memset(blob, 0, sizeof(*blob));
    blob->magic       = BLOB_MAGIC;
    blob->entry_count = 4;

    static const char *PLAINTEXTS[] = {
        "https://c2.example.net/beacon/checkin",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "cmd.exe /c schtasks /create /sc minute /mo 15 /tn Updater",
        "AppData\\Local\\Temp\\svchost_update.dat",
    };

    uint16_t offset = 0;
    for (int i = 0; i < 4; i++) {
        uint16_t len = (uint16_t)strlen(PLAINTEXTS[i]);
        blob->entries[i].offset   = offset;
        blob->entries[i].length   = len;
        blob->entries[i].rol_bits = ROL_BITS;
        blob->entries[i].xor_key  = XOR_KEY;

        encode_string(blob->payload + offset, PLAINTEXTS[i],
                      (int)len, ROL_BITS, XOR_KEY);
        offset += len;
    }
}

int main(void)
{
    puts("=== Multilayer Encode Test ===");

    /* Build the encoded blob (simulates what would be hardcoded in
     * a real sample). */
    EncodedBlob blob;
    init_blob(&blob);

    /* Validate magic before decoding -- this is the anchor constant
     * that a reverse engineer can search for in the binary. */
    if (blob.magic != BLOB_MAGIC) {
        puts("ERROR: blob magic mismatch");
        return 1;
    }

    printf("blob: magic=0x%08X entries=%u\n", blob.magic, blob.entry_count);

    /* Decode and print each entry */
    for (int i = 0; i < blob.entry_count; i++) {
        char decoded[256];
        decode_entry(decoded, blob.payload, &blob.entries[i]);
        printf("  [%d] (off=%u len=%u) -> %s\n",
               i, blob.entries[i].offset, blob.entries[i].length, decoded);
    }

    puts("marker:multilayer_encode");
    puts("marker:c2_indicators");
    return 0;
}
