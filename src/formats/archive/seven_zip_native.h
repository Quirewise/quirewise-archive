#ifndef QUIREWISE_SEVEN_ZIP_NATIVE_H
#define QUIREWISE_SEVEN_ZIP_NATIVE_H

#include <stddef.h>
#include <stdint.h>

typedef enum QwSevenZipHeaderResult {
    QW_SEVEN_ZIP_HEADER_INVALID = 0,
    QW_SEVEN_ZIP_HEADER_NATIVE = 1,
    QW_SEVEN_ZIP_HEADER_UNSUPPORTED = 2
} QwSevenZipHeaderResult;

typedef struct QwSevenZipHeader {
    const uint8_t *bytes;
    size_t size;
    size_t next_header_offset;
    uint8_t *owned_bytes;
} QwSevenZipHeader;

QwSevenZipHeaderResult qw_seven_zip_header_open(
    const void *data, size_t size, QwSevenZipHeader *out_header);
void qw_seven_zip_header_close(QwSevenZipHeader *header);

#endif
