#ifndef QUIREWISE_SEVEN_ZIP_H
#define QUIREWISE_SEVEN_ZIP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum QwSevenZipStatus {
    QW_SEVEN_ZIP_OK = 0,
    QW_SEVEN_ZIP_INVALID_ARGUMENT = 1,
    QW_SEVEN_ZIP_UNSUPPORTED = 2,
    QW_SEVEN_ZIP_DECODE_ERROR = 3,
    QW_SEVEN_ZIP_RESOURCE_LIMIT = 4,
    QW_SEVEN_ZIP_SINK_ERROR = 5,
    QW_SEVEN_ZIP_OUT_OF_MEMORY = 6,
    QW_SEVEN_ZIP_FORMAT_ERROR = 7
} QwSevenZipStatus;

typedef struct QwSevenZipSink {
    void *context;
    int (*begin)(void *context, uint32_t archive_index, const char *utf8_name,
                 uint64_t declared_size, int is_directory, void **out_entry);
    int (*write)(void *context, void *entry, const void *data, size_t size);
    void (*finish)(void *context, void *entry, int operation_result);
} QwSevenZipSink;

/* Validates the 7z signature/start header and optionally returns next offset. */
QwSevenZipStatus qw_seven_zip_probe(const void *data,
                                   size_t size,
                                   size_t *out_next_header_offset);

/*
 * Extracts supported 7z entries through a caller-provided sink. The input is
 * borrowed during the call. The optional password is UTF-8. Each entry name is
 * borrowed until finish is called for that entry.
 */
QwSevenZipStatus qw_seven_zip_extract(const void *data,
                                     size_t size,
                                     const char *password,
                                     const QwSevenZipSink *sink);

#ifdef __cplusplus
}
#endif

#endif
