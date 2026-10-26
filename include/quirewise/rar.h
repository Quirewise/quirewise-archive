#ifndef QUIREWISE_RAR_H
#define QUIREWISE_RAR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum QwRarStatus {
    QW_RAR_OK = 0,
    QW_RAR_STOPPED = 1,
    QW_RAR_ERR_INVALID_ARGUMENT = -1,
    QW_RAR_ERR_OUT_OF_MEMORY = -2,
    QW_RAR_ERR_FORMAT = -4,
    QW_RAR_ERR_UNSUPPORTED = -5,
    QW_RAR_ERR_RESOURCE_LIMIT = -11,
    QW_RAR_ERR_CALLBACK = -100
} QwRarStatus;

typedef enum QwRarVisitAction {
    QW_RAR_VISIT_CONTINUE = 0,
    QW_RAR_VISIT_STOP = 1
} QwRarVisitAction;

typedef struct QwRarEntryView {
    /* Borrowed during the visitor call; some RAR4 names may use an OEM page. */
    const uint8_t *name;
    size_t name_size;
    /* Encoded bytes are borrowed from the archive and are not decompressed. */
    const uint8_t *packed_data;
    size_t packed_size;
    uint64_t uncompressed_size;
    uint32_t data_crc32;
    uint64_t archive_flags;
    uint64_t format_flags;
    uint64_t compression_info;
    uint32_t compression_method;
    uint8_t format_version;
    uint8_t compression_version;
    int is_directory;
    int is_stored;
    int is_solid;
    int has_data_crc32;
} QwRarEntryView;

typedef struct QwRarParseLimits {
    size_t max_entries;
    uint64_t max_entry_bytes;
    uint64_t max_total_bytes;
} QwRarParseLimits;

typedef QwRarVisitAction (*QwRarEntryVisitor)(
    void *context, const QwRarEntryView *entry);

/*
 * Parses RAR4 or RAR5 headers and visits entry metadata. It does not decompress
 * entry contents. A NULL limits pointer uses conservative built-in limits.
 * Returning QW_RAR_VISIT_STOP stops after the current entry and returns
 * QW_RAR_STOPPED. Names and packed_data are borrowed during each callback.
 */
QwRarStatus qw_rar_archive_visit(const void *data,
                                 size_t size,
                                 const QwRarParseLimits *limits,
                                 QwRarEntryVisitor visitor,
                                 void *context);

#ifdef __cplusplus
}
#endif

#endif
