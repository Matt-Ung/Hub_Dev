int main(void) {
    BlobCatalog catalog = {
        .records = {
            {
                .header = {
                    .magic = 0xB10B5EEDu,
                    .version = 1,
                    .flags = 0x0003u,
                    .payload_len = 30,
                    .xor_key = 0x5Au,
                    .reserved = {0, 0, 0},
                },
                .payload = {
                    0x09, 0x0E, 0x1B, 0x1D, 0x1F, 0x1E, 0x60, 0x7A, 0x39, 0x37,
                    0x3E, 0x74, 0x3F, 0x22, 0x3F, 0x7A, 0x75, 0x39, 0x7A, 0x3F,
                    0x39, 0x32, 0x35, 0x7A, 0x36, 0x35, 0x3B, 0x3E, 0x3F, 0x28,
                },
            },
            {
                .header = {
                    .magic = 0x0u,
                    .version = 0,
                    .flags = 0,
                    .payload_len = 0,
                    .xor_key = 0,
                    .reserved = {0, 0, 0},
                },
                .payload = {0},
            },
        },
        .count = 2,
    };

    DecodeReport report;
    memset(&report, 0, sizeof(report));

    if (!decode_record(&catalog.records[0], &report)) {
        puts("decode_failed");
        return 1;
    }

    puts("marker:resource_blob_container");
    puts("marker:staged_decode_path");
    printf("decoded_payload=%s\n", report.decoded);
    printf("decoded_len=%zu\n", report.decoded_len);
    printf("checksum=0x%08x\n", report.checksum);
    return 0;
}
