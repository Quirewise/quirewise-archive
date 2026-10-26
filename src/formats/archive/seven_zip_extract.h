#ifndef QUIREWISE_SEVEN_ZIP_EXTRACT_H
#define QUIREWISE_SEVEN_ZIP_EXTRACT_H

#include <stddef.h>
#include <stdint.h>

typedef struct QwSevenZipSink {
    void *context;
    int (*begin)(void *context, uint32_t archive_index, const char *utf8_name,
                 uint64_t declared_size, int is_directory, void **out_entry);
    int (*write)(void *context, void *entry, const void *data, size_t size);
    void (*finish)(void *context, void *entry, int operation_result);
} QwSevenZipSink;

enum QwSevenZipExtractResult {
    QW_SEVEN_ZIP_EXTRACT_OK = 0,
    QW_SEVEN_ZIP_EXTRACT_INVALID = 1,
    QW_SEVEN_ZIP_EXTRACT_UNSUPPORTED = 2,
    QW_SEVEN_ZIP_EXTRACT_DECODE_ERROR = 3,
    QW_SEVEN_ZIP_EXTRACT_RESOURCE_LIMIT = 4,
    QW_SEVEN_ZIP_EXTRACT_SINK_ERROR = 5,
    QW_SEVEN_ZIP_EXTRACT_OUT_OF_MEMORY = 6
};

int qw_seven_zip_extract_memory(const void *data, size_t size,
                                const char *password,
                                const QwSevenZipSink *sink);

#endif
