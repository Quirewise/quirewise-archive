#ifndef QUIREWISE_RAR_PARSER_H
#define QUIREWISE_RAR_PARSER_H

#include <stddef.h>
#include <stdint.h>

typedef struct QwRarEntry {
    /* name and packed_data are borrowed from the input (or a temporary decoded
     * RAR4 filename) and are valid only for the duration of the visitor call.
     */
    const uint8_t *name;
    size_t name_size;
    /* Encoded bytes in the archive. The parser never decodes this buffer. */
    const uint8_t *packed_data;
    size_t packed_size;
    uint64_t uncompressed_size;
    /* Expected checksum of decoded bytes, when present in the format. */
    uint32_t data_crc32;
    /* Raw archive and per-entry flags, plus version-specific compression data. */
    uint64_t archive_flags;
    uint64_t format_flags;
    uint64_t compression_info;
    /* Normalized method number. RAR4 unknown method bytes use UINT32_MAX;
     * RAR5 reserved method values are preserved for downstream dispatch.
     */
    uint32_t compression_method;
    uint8_t format_version;
    uint8_t compression_version;
    int is_directory;
    int is_stored;
    int is_solid;
    int has_data_crc32;
} QwRarEntry;

typedef struct QwRarLimits {
    size_t max_entries;
    uint64_t max_entry_bytes;
    uint64_t max_total_bytes;
} QwRarLimits;

typedef int (*QwRarEntryFn)(void *context, const QwRarEntry *entry);

#endif
