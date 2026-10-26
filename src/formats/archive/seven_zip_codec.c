#include "seven_zip_codec.h"

#include <lzma.h>
#include <limits.h>
#include <string.h>
#include <zlib.h>

enum {
    SEVEN_ZIP_COPY_METHOD = 0x00u,
    SEVEN_ZIP_DELTA_METHOD = 0x03u,
    SEVEN_ZIP_LZMA1_METHOD = 0x030101u,
    SEVEN_ZIP_LZMA2_METHOD = 0x21u,
    SEVEN_ZIP_DEFLATE_METHOD = 0x040108u,
    SEVEN_ZIP_X86_METHOD = 0x03030103u,
    SEVEN_ZIP_POWERPC_METHOD = 0x03030205u,
    SEVEN_ZIP_IA64_METHOD = 0x03030401u,
    SEVEN_ZIP_ARM_METHOD = 0x03030501u,
    SEVEN_ZIP_ARMTHUMB_METHOD = 0x03030701u,
    SEVEN_ZIP_SPARC_METHOD = 0x03030805u
};

#define SEVEN_ZIP_DECODER_MEMORY_LIMIT (256u * 1024u * 1024u)

static int seven_zip_inflate_deflate(const uint8_t *packed,
                                     size_t packed_size,
                                     uint8_t *decoded,
                                     size_t decoded_size)
{
    z_stream stream = {0};
    int inflate_result;
    int end_result;

    if (!packed || !packed_size || !decoded || !decoded_size ||
        packed_size > UINT_MAX || decoded_size > UINT_MAX) {
        return 0;
    }
    stream.next_in = (Bytef *)(void *)packed;
    stream.avail_in = (uInt)packed_size;
    stream.next_out = decoded;
    stream.avail_out = (uInt)decoded_size;
    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) return 0;
    inflate_result = inflate(&stream, Z_FINISH);
    end_result = inflateEnd(&stream);
    return inflate_result == Z_STREAM_END && end_result == Z_OK &&
           stream.total_in == (uLong)packed_size &&
           stream.total_out == (uLong)decoded_size;
}

static int seven_zip_map_filter(uint32_t method, lzma_vli *out_filter)
{
    switch (method) {
    case SEVEN_ZIP_DELTA_METHOD: *out_filter = LZMA_FILTER_DELTA; return 1;
    case SEVEN_ZIP_LZMA1_METHOD: *out_filter = LZMA_FILTER_LZMA1; return 1;
    case SEVEN_ZIP_LZMA2_METHOD: *out_filter = LZMA_FILTER_LZMA2; return 1;
    case SEVEN_ZIP_X86_METHOD: *out_filter = LZMA_FILTER_X86; return 1;
    case SEVEN_ZIP_POWERPC_METHOD: *out_filter = LZMA_FILTER_POWERPC; return 1;
    case SEVEN_ZIP_IA64_METHOD: *out_filter = LZMA_FILTER_IA64; return 1;
    case SEVEN_ZIP_ARM_METHOD: *out_filter = LZMA_FILTER_ARM; return 1;
    case SEVEN_ZIP_ARMTHUMB_METHOD:
        *out_filter = LZMA_FILTER_ARMTHUMB;
        return 1;
    case SEVEN_ZIP_SPARC_METHOD: *out_filter = LZMA_FILTER_SPARC; return 1;
    default: return 0;
    }
}

int qw_seven_zip_decode_chain(const QwSevenZipCoder *coders,
                              size_t coder_count,
                              const uint8_t *packed, size_t packed_size,
                              uint8_t *decoded, size_t decoded_size)
{
    lzma_filter filters[QW_SEVEN_ZIP_MAX_CODERS + 1u];
    size_t filter_count = 0u;
    size_t input_position = 0u;
    size_t output_position = 0u;
    uint64_t decoder_memory;
    lzma_ret lzrc;
    const uint8_t no_properties = 0u;
    size_t deflate_count = 0u;
    size_t active_coder_count = 0u;
    size_t deflate_index = SIZE_MAX;
    if (!coders || !coder_count ||
        coder_count > QW_SEVEN_ZIP_MAX_CODERS ||
        (!packed && packed_size) || !packed_size || !decoded || !decoded_size)
        return 0;
    for (size_t i = 0u; i < QW_SEVEN_ZIP_MAX_CODERS + 1u; ++i) {
        filters[i].id = LZMA_VLI_UNKNOWN;
        filters[i].options = NULL;
    }
    for (size_t i = 0u; i < coder_count; ++i) {
        if (coders[i].method == SEVEN_ZIP_COPY_METHOD) {
            if (coders[i].properties_size) return 0;
            continue;
        }
        ++active_coder_count;
        if (coders[i].method == SEVEN_ZIP_DEFLATE_METHOD) {
            ++deflate_count;
            deflate_index = i;
        }
    }
    if (deflate_count) {
        if (deflate_count != 1u || active_coder_count != 1u ||
            deflate_index == SIZE_MAX ||
            coders[deflate_index].properties_size != 0u) {
            return 0;
        }
        return seven_zip_inflate_deflate(packed, packed_size, decoded,
                                         decoded_size);
    }
    for (size_t i = coder_count; i > 0u; --i) {
        const QwSevenZipCoder *coder = &coders[i - 1u];
        lzma_vli filter_id;
        const uint8_t *properties = coder->properties
            ? coder->properties : &no_properties;
        if (coder->method == SEVEN_ZIP_COPY_METHOD) {
            if (coder->properties_size) goto error;
            continue;
        }
        if (filter_count >= QW_SEVEN_ZIP_MAX_CODERS ||
            !seven_zip_map_filter(coder->method, &filter_id) ||
            coder->properties_size > UINT32_MAX ||
            (coder->properties_size && !coder->properties)) goto error;
        filters[filter_count].id = filter_id;
        filters[filter_count].options = NULL;
        lzrc = lzma_properties_decode(&filters[filter_count], NULL,
                                      properties,
                                      (uint32_t)coder->properties_size);
        if (lzrc != LZMA_OK) goto error;
        ++filter_count;
    }
    if (!filter_count) {
        if (packed_size != decoded_size) return 0;
        memcpy(decoded, packed, decoded_size);
        return 1;
    }
    filters[filter_count].id = LZMA_VLI_UNKNOWN;
    filters[filter_count].options = NULL;
    decoder_memory = lzma_raw_decoder_memusage(filters);
    if (decoder_memory == UINT64_MAX ||
        decoder_memory > (uint64_t)SEVEN_ZIP_DECODER_MEMORY_LIMIT) goto error;
    lzrc = lzma_raw_buffer_decode(filters, NULL, packed, &input_position,
                                  packed_size, decoded, &output_position,
                                  decoded_size);
    lzma_filters_free(filters, NULL);
    return lzrc == LZMA_OK && input_position == packed_size &&
           output_position == decoded_size;
error:
    lzma_filters_free(filters, NULL);
    return 0;
}
