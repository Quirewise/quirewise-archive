#ifndef QW_ZIP_DEFLATE_H
#define QW_ZIP_DEFLATE_H

#include <stddef.h>
#include <stdint.h>

uint32_t qw_zip_crc32(const uint8_t *data, size_t size);
int qw_zip_inflate_raw(const uint8_t *input, size_t input_size,
                       uint8_t *output, size_t output_size);
int qw_zip_deflate_raw_stored(const uint8_t *input, size_t input_size,
                              uint8_t **out_data, size_t *out_size);

#endif
