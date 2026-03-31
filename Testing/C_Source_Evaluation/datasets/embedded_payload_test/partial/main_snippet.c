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
