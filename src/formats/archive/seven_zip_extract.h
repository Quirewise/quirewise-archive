#ifndef QUIREWISE_SEVEN_ZIP_EXTRACT_H
#define QUIREWISE_SEVEN_ZIP_EXTRACT_H

#include <quirewise/seven_zip.h>

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
