#ifndef QUIREWISE_SEVEN_ZIP_CODEC_H
#define QUIREWISE_SEVEN_ZIP_CODEC_H

#include <quirewise/compression.h>

enum { QW_SEVEN_ZIP_MAX_CODERS = QW_COMPRESSION_7Z_MAX_CODERS };

typedef QwCompression7zCoder QwSevenZipCoder;

int qw_seven_zip_decode_chain(const QwSevenZipCoder *coders,
                              size_t coder_count,
                              const uint8_t *packed, size_t packed_size,
                              uint8_t *decoded, size_t decoded_size);

#endif
