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
