/*
 * File:       embedded_payload_test.c
 * Purpose:    Simulates a binary with an embedded, encoded payload blob
 *             that is extracted and decoded at runtime through a staged
 *             process: locate header -> validate checksum -> decode
 *             payload -> parse records.  This pattern mimics droppers,
 *             loaders, and self-extracting malware.
 *
 * Difficulty: HARD
 *
 * Techniques:
 *   - Embedded binary blob with structured header (magic, version,
 *     checksum, payload offset)
 *   - CRC32-style rolling checksum for integrity validation
 *   - Multi-record payload: each record has its own type tag,
 *     length, and XOR key
 *   - Staged extraction: header parse -> checksum -> per-record decode
 *   - Decoded records contain file paths, URLs, and configuration data
 *   - Dead/padding records with type=0xFF to confuse linear scanning
 *
 * Why it matters for testing:
 *   This exercises the full chain of binary analysis tools:
 *     (a) binwalk should detect the embedded blob via magic signature
 *     (b) strings/FLOSS should recover decoded record contents
 *     (c) Ghidra should reconstruct the header parsing, checksum
 *         algorithm, and per-record decode loop
 *     (d) capa should flag "embedded payload", "decode data",
 *         "validate checksum"
 *
 *   The UPX MCP server can be exercised by packing this binary
 *   post-compilation (the Makefile includes a UPX target).
 *
 *   The multi-record structure tests whether the planner generates
 *   separate work items for header analysis vs. payload analysis.
 *
 * Expected analysis signals:
 *   - Magic value 0x504C4F44 ("PLOD") visible in binary
 *   - binwalk may flag the embedded structure
 *   - Decoded records contain:
 *       type 0x01: "C:\\Windows\\Temp\\stage2.dll"
 *       type 0x02: "https://dl.example.org/payload/v3"
 *       type 0x03: "interval=300;retry=5;jitter=30"
 *   - Dead records (type 0xFF) contain garbage / padding
 *   - Checksum algorithm visible in Ghidra (rotate-left + XOR)
 *   - capa: "encode data via XOR", "validate data checksum"
 *
 * Recommended MCP servers / tools:
 *   - binwalkmcp      : detect embedded blob via magic/signature
 *   - flareflossmcp   : recover decoded record strings
 *   - stringmcp       : cleartext format strings, magic bytes
 *   - ghidramcp       : decompilation of header parse, checksum,
 *                        record decode loop
 *   - CapaMCP         : behavioral rules for payload embedding,
 *                        checksum validation, XOR decode
 *   - upxmcp          : if the packed variant is analyzed
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------
 * Blob header constants.
 * "PLOD" in little-endian = 0x504C4F44.
 * --------------------------------------------------------------- */
#define PAYLOAD_MAGIC   0x504C4F44u
#define PAYLOAD_VERSION 2

/* ---------------------------------------------------------------
 * Record type tags.
 * 0x01 = file path, 0x02 = URL, 0x03 = config string, 0xFF = dead
 * --------------------------------------------------------------- */
#define REC_TYPE_PATH   0x01
#define REC_TYPE_URL    0x02
#define REC_TYPE_CONFIG 0x03
#define REC_TYPE_DEAD   0xFF

/* ---------------------------------------------------------------
 * PayloadHeader -- precedes the encoded records.
 * A reverse engineer should find this struct at a known offset
 * and use the magic + version to orient their analysis.
 * --------------------------------------------------------------- */
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t record_count;
    uint32_t total_payload_len;
    uint32_t checksum;  /* computed over the payload bytes only */
} PayloadHeader;

/*
 * PayloadRecord -- one encoded record within the payload.
 * The `xor_key` is per-record, so each record must be decoded
 * independently.  This prevents a single-key brute force from
 * recovering everything at once.
 */
typedef struct {
    uint8_t  type;
    uint8_t  xor_key;
    uint16_t data_len;
    uint8_t  data[128];
} PayloadRecord;

/*
 * EmbeddedPayload -- the complete blob (header + records).
 */
typedef struct {
    PayloadHeader header;
    PayloadRecord records[5];
} EmbeddedPayload;

/* ---------------------------------------------------------------
 * rolling_checksum -- CRC32-style checksum using rotate-left and
 * XOR.  This is intentionally a simple, recognizable pattern that
 * Ghidra should decompile cleanly.
 * --------------------------------------------------------------- */
static uint32_t rolling_checksum(const uint8_t *buf, uint32_t len)
{
    uint32_t acc = 0x12345678u;
    for (uint32_t i = 0; i < len; i++) {
        /* rotate left by 5 */
        acc = (acc << 5) | (acc >> 27);
        acc ^= (uint32_t)buf[i];
        acc += 0x9E3779B9u;  /* golden ratio constant, common in hash funcs */
    }
    return acc;
}

/* ---------------------------------------------------------------
 * xor_encode -- encode plaintext into a record's data field.
 * --------------------------------------------------------------- */
static void xor_encode(uint8_t *out, const char *plain, int len, uint8_t key)
{
    for (int i = 0; i < len; i++) {
        out[i] = (uint8_t)plain[i] ^ key;
    }
}

/* ---------------------------------------------------------------
 * xor_decode -- decode a record's data field to plaintext.
 * --------------------------------------------------------------- */
static void xor_decode(char *out, const uint8_t *enc, int len, uint8_t key)
{
    for (int i = 0; i < len; i++) {
        out[i] = (char)(enc[i] ^ key);
    }
    out[len] = '\0';
}

/* ---------------------------------------------------------------
 * init_payload -- constructs the embedded payload blob at runtime.
 * In a real dropper, these bytes would be hardcoded in the .data
 * or a resource section.  We construct them here for source-level
 * readability.
 * --------------------------------------------------------------- */
static void init_payload(EmbeddedPayload *p)
{
    memset(p, 0, sizeof(*p));

    /* Header */
    p->header.magic        = PAYLOAD_MAGIC;
    p->header.version      = PAYLOAD_VERSION;
    p->header.record_count = 5;

    /* Record 0: file path (type 0x01, key 0xAA) */
    static const char *path = "C:\\Windows\\Temp\\stage2.dll";
    p->records[0].type     = REC_TYPE_PATH;
    p->records[0].xor_key  = 0xAA;
    p->records[0].data_len = (uint16_t)strlen(path);
    xor_encode(p->records[0].data, path, (int)strlen(path), 0xAA);

    /* Record 1: URL (type 0x02, key 0x55) */
    static const char *url = "https://dl.example.org/payload/v3";
    p->records[1].type     = REC_TYPE_URL;
    p->records[1].xor_key  = 0x55;
    p->records[1].data_len = (uint16_t)strlen(url);
    xor_encode(p->records[1].data, url, (int)strlen(url), 0x55);

    /* Record 2: dead/padding (type 0xFF) -- decoy to confuse scanners */
    p->records[2].type     = REC_TYPE_DEAD;
    p->records[2].xor_key  = 0x00;
    p->records[2].data_len = 16;
    memset(p->records[2].data, 0xCC, 16);  /* INT3 padding pattern */

    /* Record 3: config string (type 0x03, key 0x37) */
    static const char *cfg = "interval=300;retry=5;jitter=30";
    p->records[3].type     = REC_TYPE_CONFIG;
    p->records[3].xor_key  = 0x37;
    p->records[3].data_len = (uint16_t)strlen(cfg);
    xor_encode(p->records[3].data, cfg, (int)strlen(cfg), 0x37);

    /* Record 4: another dead/padding entry */
    p->records[4].type     = REC_TYPE_DEAD;
    p->records[4].xor_key  = 0x00;
    p->records[4].data_len = 8;
    memset(p->records[4].data, 0x90, 8);  /* NOP sled pattern */

    /* Compute checksum over all record bytes */
    uint32_t total = 0;
    for (int i = 0; i < 5; i++) {
        total += (uint32_t)(4 + p->records[i].data_len);  /* type+key+len+data */
    }
    p->header.total_payload_len = total;
    p->header.checksum = rolling_checksum(
        (const uint8_t *)p->records,
        (uint32_t)(5 * sizeof(PayloadRecord))
    );
}

/* ---------------------------------------------------------------
 * extract_and_decode -- validates the header, checks the checksum,
 * and decodes each non-dead record.
 *
 * This function is the primary analysis target.  The staged
 * process (magic check -> checksum -> per-record decode) should
 * appear clearly in Ghidra decompilation.
 * --------------------------------------------------------------- */
static int extract_and_decode(const EmbeddedPayload *p)
{
    /* Step 1: validate magic */
    if (p->header.magic != PAYLOAD_MAGIC) {
        puts("ERROR: payload magic mismatch");
        return -1;
    }
    printf("header: magic=0x%08X version=%u records=%u payload_len=%u\n",
           p->header.magic, p->header.version,
           p->header.record_count, p->header.total_payload_len);

    /* Step 2: validate checksum */
    uint32_t computed = rolling_checksum(
        (const uint8_t *)p->records,
        (uint32_t)(p->header.record_count * sizeof(PayloadRecord))
    );
    if (computed != p->header.checksum) {
        printf("ERROR: checksum mismatch (expected=0x%08X computed=0x%08X)\n",
               p->header.checksum, computed);
        return -2;
    }
    printf("checksum OK: 0x%08X\n", computed);

    /* Step 3: decode each record */
    for (int i = 0; i < p->header.record_count; i++) {
        const PayloadRecord *rec = &p->records[i];

        if (rec->type == REC_TYPE_DEAD) {
            printf("  record[%d]: type=0x%02X (dead/padding), skipped\n",
                   i, rec->type);
            continue;
        }

        char decoded[256];
        xor_decode(decoded, rec->data, (int)rec->data_len, rec->xor_key);

        const char *type_label;
        switch (rec->type) {
            case REC_TYPE_PATH:   type_label = "PATH";   break;
            case REC_TYPE_URL:    type_label = "URL";     break;
            case REC_TYPE_CONFIG: type_label = "CONFIG";  break;
            default:              type_label = "UNKNOWN"; break;
        }

        printf("  record[%d]: type=0x%02X (%s) key=0x%02X -> %s\n",
               i, rec->type, type_label, rec->xor_key, decoded);
    }

    return 0;
}

int main(void)
{
    puts("=== Embedded Payload Test ===");

    EmbeddedPayload payload;
    init_payload(&payload);

    int rc = extract_and_decode(&payload);
    if (rc != 0) {
        printf("extraction failed with code %d\n", rc);
        return 1;
    }

    puts("marker:embedded_payload");
    puts("marker:staged_extraction");
    return 0;
}
