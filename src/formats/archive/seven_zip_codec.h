#ifndef QUIREWISE_SEVEN_ZIP_CODEC_H
#define QUIREWISE_SEVEN_ZIP_CODEC_H

#include <stddef.h>
#include <stdint.h>

enum { QW_SEVEN_ZIP_MAX_CODERS = 4u };

typedef struct QwSevenZipCoder {
    uint32_t method;
    const uint8_t *properties;
    size_t properties_size;
} QwSevenZipCoder;

int qw_seven_zip_decode_chain(const QwSevenZipCoder *coders,
                              size_t coder_count,
                              const uint8_t *packed, size_t packed_size,
                              uint8_t *decoded, size_t decoded_size);

#endif
