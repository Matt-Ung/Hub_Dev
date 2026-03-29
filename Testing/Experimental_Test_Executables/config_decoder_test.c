/*
 * File:       config_decoder_test.c
 * Purpose:    Simulates a program that carries an embedded configuration
 *             block encoded with a simple single-byte XOR cipher.  The
 *             config contains a file path, a numeric port, and a flag
 *             string.  At runtime the program decodes the block, parses
 *             the key=value pairs, and prints them.
 *
 * Difficulty: MEDIUM
 *
 * Techniques:
 *   - Single-byte XOR encoding of an embedded config blob
 *   - Key=value line parsing with validation
 *   - Multiple function calls with error-return propagation
 *   - Stack buffer manipulation (decode into local array)
 *   - Struct-based parsed configuration
 *
 * Why it matters for testing:
 *   This is the simplest non-trivial encoding pattern that FLOSS is
 *   designed to recover.  If the analysis pipeline's FLOSS integration
 *   cannot produce the decoded config strings, either the tool call is
 *   wrong or the agent is not inspecting FLOSS output.  The config
 *   values (path, port, flag) serve as concrete "expected evidence"
 *   entries in the scoring rubric.
 *
 *   The parsing logic adds branching complexity beyond a simple decode
 *   loop, giving the planner meaningful work items (decode routine vs.
 *   parser vs. validation).
 *
 * Expected analysis signals:
 *   - FLOSS recovers decoded strings: "C:\\ProgramData\\agent\\config.ini",
 *     "8443", "persist=true"
 *   - Ghidra decompilation shows the XOR loop and key=value parser
 *   - capa may flag "decode data via XOR" or "parse configuration"
 *   - strings tool finds the encoded blob as non-printable data and
 *     the printf format strings as cleartext
 *
 * Recommended MCP servers / tools:
 *   - flareflossmcp   : primary; should recover decoded config lines
 *   - stringmcp       : cleartext format strings + raw encoded blob
 *   - ghidramcp       : decompilation of xor_decode and parse_config
 *   - CapaMCP         : XOR decode behavioral rule
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------
 * XOR key used for encoding.  A single-byte key is deliberately
 * weak -- the point is to test tool integration, not to defeat
 * analysis.
 * --------------------------------------------------------------- */
#define CONFIG_XOR_KEY 0x4B

/* ---------------------------------------------------------------
 * Encoded configuration blob.
 * Plaintext (before XOR with 0x4B):
 *   "path=C:\\ProgramData\\agent\\config.ini\n"
 *   "port=8443\n"
 *   "flag=persist=true\n"
 *
 * Each byte is plaintext[i] ^ 0x4B.
 * --------------------------------------------------------------- */
static const uint8_t ENCODED_CONFIG[] = {
    /* "path=C:\ProgramData\agent\config.ini\nport=8443\nflag=persist=true\n"
     * XOR key = 0x4B, 65 bytes total */
    0x3b, 0x2a, 0x3f, 0x23, 0x76, 0x08, 0x71, 0x17, 0x1b, 0x39, 0x24, 0x2c,
    0x39, 0x2a, 0x26, 0x0f, 0x2a, 0x3f, 0x2a, 0x17, 0x2a, 0x2c, 0x2e, 0x25,
    0x3f, 0x17, 0x28, 0x24, 0x25, 0x2d, 0x22, 0x2c, 0x65, 0x22, 0x25, 0x22,
    0x41, 0x3b, 0x24, 0x39, 0x3f, 0x76, 0x73, 0x7f, 0x7f, 0x78, 0x41, 0x2d,
    0x27, 0x2a, 0x2c, 0x76, 0x3b, 0x2e, 0x39, 0x38, 0x22, 0x38, 0x3f, 0x76,
    0x3f, 0x39, 0x3e, 0x2e, 0x41,
};

#define ENCODED_CONFIG_LEN ((int)sizeof(ENCODED_CONFIG))

/* ---------------------------------------------------------------
 * ParsedConfig -- holds the extracted key=value pairs.
 * A reverse engineer should see these fields populated after
 * the decode and parse steps.
 * --------------------------------------------------------------- */
typedef struct {
    char path[128];
    int  port;
    char flag[64];
} ParsedConfig;

/* ---------------------------------------------------------------
 * xor_decode -- single-byte XOR decode into a caller-supplied
 * buffer.  The function null-terminates the output.
 *
 * This is the primary target for FLOSS stack-string / decoded-string
 * recovery.
 * --------------------------------------------------------------- */
static void xor_decode(char *out, const uint8_t *enc, int len, uint8_t key)
{
    for (int i = 0; i < len; i++) {
        out[i] = (char)(enc[i] ^ key);
    }
    out[len] = '\0';
}

/* ---------------------------------------------------------------
 * parse_line -- extracts a key=value pair from a single line.
 * Returns 0 on success, -1 if the line is malformed.
 *
 * The branching here (key match, missing '=', empty value) adds
 * medium-level control-flow complexity.
 * --------------------------------------------------------------- */
static int parse_line(ParsedConfig *cfg, const char *line, int linelen)
{
    /* Find the '=' separator */
    const char *eq = NULL;
    for (int i = 0; i < linelen; i++) {
        if (line[i] == '=') {
            eq = &line[i];
            break;
        }
    }
    if (!eq)
        return -1;

    int keylen = (int)(eq - line);
    const char *val = eq + 1;
    int vallen = linelen - keylen - 1;

    if (keylen == 4 && memcmp(line, "path", 4) == 0) {
        if (vallen >= (int)sizeof(cfg->path))
            vallen = (int)sizeof(cfg->path) - 1;
        memcpy(cfg->path, val, (size_t)vallen);
        cfg->path[vallen] = '\0';
    } else if (keylen == 4 && memcmp(line, "port", 4) == 0) {
        /* Simple atoi without stdlib to keep the binary minimal */
        int p = 0;
        for (int i = 0; i < vallen; i++) {
            if (val[i] < '0' || val[i] > '9')
                return -1;
            p = p * 10 + (val[i] - '0');
        }
        cfg->port = p;
    } else if (keylen == 4 && memcmp(line, "flag", 4) == 0) {
        if (vallen >= (int)sizeof(cfg->flag))
            vallen = (int)sizeof(cfg->flag) - 1;
        memcpy(cfg->flag, val, (size_t)vallen);
        cfg->flag[vallen] = '\0';
    } else {
        /* Unknown key -- skip */
        return 0;
    }

    return 0;
}

/* ---------------------------------------------------------------
 * parse_config -- splits a decoded config buffer on '\n' and feeds
 * each line to parse_line.
 * --------------------------------------------------------------- */
static int parse_config(ParsedConfig *cfg, const char *buf, int len)
{
    const char *start = buf;
    int count = 0;

    for (int i = 0; i <= len; i++) {
        if (i == len || buf[i] == '\n') {
            int linelen = (int)(&buf[i] - start);
            if (linelen > 0) {
                if (parse_line(cfg, start, linelen) < 0) {
                    printf("  [warn] malformed config line at offset %d\n",
                           (int)(start - buf));
                }
                count++;
            }
            start = &buf[i + 1];
        }
    }
    return count;
}

int main(void)
{
    puts("=== Config Decoder Test ===");

    /* Step 1: decode the embedded config blob */
    char decoded[256];
    xor_decode(decoded, ENCODED_CONFIG, ENCODED_CONFIG_LEN, CONFIG_XOR_KEY);
    printf("decoded %d bytes of config\n", ENCODED_CONFIG_LEN);

    /* Step 2: parse key=value pairs */
    ParsedConfig cfg;
    memset(&cfg, 0, sizeof(cfg));

    int lines = parse_config(&cfg, decoded, (int)strlen(decoded));
    printf("parsed %d config lines\n", lines);

    /* Step 3: print results */
    printf("  path = %s\n", cfg.path);
    printf("  port = %d\n", cfg.port);
    printf("  flag = %s\n", cfg.flag);

    puts("marker:config_decoder");
    return 0;
}
