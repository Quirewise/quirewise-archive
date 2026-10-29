#include "seven_zip_codec.h"

#define SEVEN_ZIP_DECODER_MEMORY_LIMIT (256u * 1024u * 1024u)

int qw_seven_zip_decode_chain(const QwSevenZipCoder *coders,
                              size_t coder_count,
                              const uint8_t *packed, size_t packed_size,
                              uint8_t *decoded, size_t decoded_size)
{
    return qw_compression_inflate_7z_chain(
        coders, coder_count, packed, packed_size, decoded, decoded_size,
        SEVEN_ZIP_DECODER_MEMORY_LIMIT);
}
