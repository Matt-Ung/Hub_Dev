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
