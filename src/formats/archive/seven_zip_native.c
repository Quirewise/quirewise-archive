#include "seven_zip_native.h"
#include "seven_zip_files_info.h"
#include "seven_zip_streams.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>

/* Parses direct headers and one-folder encoded headers with linear coder
 * chains. Unsupported coder graphs and external filename streams are rejected. */
enum {
    SEVEN_ZIP_START_HEADER_SIZE = 32u,
    SEVEN_ZIP_NEXT_HEADER_LIMIT = 16 * 1024 * 1024,
    SEVEN_ZIP_ID_HEADER = 0x01u,
    SEVEN_ZIP_ID_ENCODED_HEADER = 0x17u,
    SEVEN_ZIP_ID_END = 0x00u
};



static uint32_t seven_zip_read_u32_le(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static uint64_t seven_zip_read_u64_le(const uint8_t *data)
{
    return (uint64_t)seven_zip_read_u32_le(data) |
           ((uint64_t)seven_zip_read_u32_le(data + 4u) << 32);
}

static int seven_zip_decode_encoded_header(const uint8_t *archive,
                                           size_t archive_size,
                                           size_t next_header_offset,
                                           const uint8_t *encoded,
                                           size_t encoded_size,
                                           uint8_t **out_header,
                                           size_t *out_header_size)
{
    QwSevenZipStreamInfo parsed = {0};
    uint8_t *decoded = NULL;
    size_t position = 1u;
    uLong crc;
    int result = 0;
    if (!archive || !encoded || !encoded_size || !out_header ||
        !out_header_size) return 0;
    *out_header = NULL;
    *out_header_size = 0u;
    if (!qw_seven_zip_stream_info_parse(encoded, encoded_size, &position,
                                        &parsed) ||
        position >= encoded_size || encoded[position++] != SEVEN_ZIP_ID_END ||
        position != encoded_size || parsed.substream_count != 1u ||
        parsed.unpack_size > (uint64_t)SEVEN_ZIP_NEXT_HEADER_LIMIT ||
        parsed.unpack_size > (uint64_t)SIZE_MAX ||
        parsed.substreams[0].unpack_size != parsed.unpack_size) goto done;
    decoded = (uint8_t *)malloc((size_t)parsed.unpack_size);
    if (!decoded || !qw_seven_zip_stream_info_decode(
            archive, archive_size, next_header_offset, &parsed, decoded,
            (size_t)parsed.unpack_size)) goto done;
    if (parsed.substreams[0].has_crc) {
        crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, (const Bytef *)decoded,
                    (uInt)parsed.substreams[0].unpack_size);
        if ((uint32_t)crc != parsed.substreams[0].crc) goto done;
    }
    if (!parsed.unpack_size || decoded[0] != SEVEN_ZIP_ID_HEADER) goto done;
    *out_header = decoded;
    *out_header_size = (size_t)parsed.unpack_size;
    decoded = NULL;
    result = 1;
done:
    free(decoded);
    qw_seven_zip_stream_info_dispose(&parsed);
    return result;
}
QwSevenZipHeaderResult qw_seven_zip_header_open(
    const void *data, size_t size, QwSevenZipHeader *out_header)
{
    static const uint8_t signature[] = {
        0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu
    };
    const uint8_t *bytes = (const uint8_t *)data;
    uint64_t relative_offset;
    uint64_t next_header_size;
    size_t next_header_offset;
    const uint8_t *next_header;
    uint8_t *decoded_header = NULL;
    size_t decoded_header_size = 0u;
    uLong crc;
    if (out_header) *out_header = (QwSevenZipHeader){0};
    if (!bytes || !out_header || size < SEVEN_ZIP_START_HEADER_SIZE ||
        memcmp(bytes, signature, sizeof(signature)) != 0) {
        return QW_SEVEN_ZIP_HEADER_INVALID;
    }
    crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const Bytef *)(bytes + 12u), 20u);
    if ((uint32_t)crc != seven_zip_read_u32_le(bytes + 8u))
        return QW_SEVEN_ZIP_HEADER_INVALID;
    relative_offset = seven_zip_read_u64_le(bytes + 12u);
    next_header_size = seven_zip_read_u64_le(bytes + 20u);
    if (relative_offset > (uint64_t)(size - SEVEN_ZIP_START_HEADER_SIZE) ||
        next_header_size > (uint64_t)SEVEN_ZIP_NEXT_HEADER_LIMIT ||
        next_header_size > (uint64_t)SIZE_MAX ||
        next_header_size > (uint64_t)(size - SEVEN_ZIP_START_HEADER_SIZE) -
                               relative_offset) {
        return QW_SEVEN_ZIP_HEADER_INVALID;
    }
    next_header_offset = SEVEN_ZIP_START_HEADER_SIZE +
                         (size_t)relative_offset;
    next_header = bytes + next_header_offset;
    crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const Bytef *)next_header, (uInt)next_header_size);
    if ((uint32_t)crc != seven_zip_read_u32_le(bytes + 28u))
        return QW_SEVEN_ZIP_HEADER_INVALID;
    if (!next_header_size)
        return QW_SEVEN_ZIP_HEADER_UNSUPPORTED;
    if (next_header[0] == SEVEN_ZIP_ID_ENCODED_HEADER) {
        if (!seven_zip_decode_encoded_header(bytes, size, next_header_offset,
                                             next_header,
                                             (size_t)next_header_size,
                                             &decoded_header,
                                             &decoded_header_size))
            return QW_SEVEN_ZIP_HEADER_UNSUPPORTED;
        out_header->bytes = decoded_header;
        out_header->size = decoded_header_size;
        out_header->owned_bytes = decoded_header;
        out_header->next_header_offset = next_header_offset;
        return QW_SEVEN_ZIP_HEADER_NATIVE;
    }
    if (next_header[0] != SEVEN_ZIP_ID_HEADER) {
        return QW_SEVEN_ZIP_HEADER_INVALID;
    }
    out_header->bytes = next_header;
    out_header->size = (size_t)next_header_size;
    out_header->next_header_offset = next_header_offset;
    return QW_SEVEN_ZIP_HEADER_NATIVE;
}

void qw_seven_zip_header_close(QwSevenZipHeader *header)
{
    if (!header) return;
    free(header->owned_bytes);
    *header = (QwSevenZipHeader){0};
}

