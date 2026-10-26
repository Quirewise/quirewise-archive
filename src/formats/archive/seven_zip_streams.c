#include "seven_zip_streams.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

enum {
    SEVEN_ZIP_START_HEADER_SIZE = 32u,
    SEVEN_ZIP_FILE_COUNT_LIMIT = 1000000u,
    SEVEN_ZIP_ID_END = 0x00u,
    SEVEN_ZIP_ID_PACK_INFO = 0x06u,
    SEVEN_ZIP_ID_UNPACK_INFO = 0x07u,
    SEVEN_ZIP_ID_SUBSTREAMS_INFO = 0x08u,
    SEVEN_ZIP_ID_SIZE = 0x09u,
    SEVEN_ZIP_ID_CRC = 0x0au,
    SEVEN_ZIP_ID_FOLDER = 0x0bu,
    SEVEN_ZIP_ID_CODERS_UNPACK_SIZE = 0x0cu,
    SEVEN_ZIP_ID_NUM_UNPACK_STREAM = 0x0du
};

#define SEVEN_ZIP_STREAM_MEMORY_LIMIT (256u * 1024u * 1024u)

static uint32_t seven_zip_read_u32_le(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static int seven_zip_read_number(const uint8_t *data, size_t size,
                                 size_t *position, uint64_t *out_value)
{
    uint8_t first;
    uint8_t mask = 0x80u;
    uint64_t value;
    unsigned extra = 0u;
    if (!data || !position || !out_value || *position >= size) return 0;
    first = data[(*position)++];
    while (extra < 8u && (first & mask) != 0u) {
        ++extra;
        mask >>= 1;
    }
    if (extra == 8u) {
        value = 0u;
        for (unsigned i = 0u; i < 8u; ++i) {
            if (*position >= size) return 0;
            value = (value << 8) | data[(*position)++];
        }
    } else {
        value = (uint64_t)(first & (uint8_t)(mask - 1u));
        for (unsigned i = 0u; i < extra; ++i) {
            if (*position >= size) return 0;
            value = (value << 8) | data[(*position)++];
        }
    }
    *out_value = value;
    return 1;
}

static int seven_zip_read_digests(const uint8_t *data, size_t size,
                                  size_t *position, size_t count,
                                  QwSevenZipSubstream *substreams,
                                  int *out_single_defined,
                                  uint32_t *out_single_crc)
{
    uint8_t all_defined;
    size_t defined_count = 0u;
    size_t bitmap_size = 0u;
    if (!data || !position || count > SEVEN_ZIP_FILE_COUNT_LIMIT ||
        *position >= size) return 0;
    all_defined = data[(*position)++];
    if (all_defined > 1u) return 0;
    if (all_defined) {
        defined_count = count;
        if (substreams) {
            for (size_t i = 0u; i < count; ++i)
                substreams[i].has_crc = 1;
        }
        if (out_single_defined) *out_single_defined = count != 0u;
    } else {
        bitmap_size = (count + 7u) / 8u;
        if (bitmap_size > size - *position) return 0;
        for (size_t i = 0u; i < count; ++i) {
            int defined = (data[*position + (i >> 3)] &
                           (uint8_t)(1u << (i & 7u))) != 0u;
            if (defined) ++defined_count;
            if (substreams) substreams[i].has_crc = defined;
            if (i == 0u && out_single_defined) *out_single_defined = defined;
        }
        if (count % 8u && bitmap_size) {
            uint8_t unused_mask = (uint8_t)(0xffu << (count % 8u));
            if (data[*position + bitmap_size - 1u] & unused_mask) return 0;
        }
        *position += bitmap_size;
    }
    if (defined_count > (size - *position) / 4u) return 0;
    for (size_t i = 0u; i < count; ++i) {
        int defined = all_defined ||
            (bitmap_size && (data[*position - bitmap_size + (i >> 3)] &
                             (uint8_t)(1u << (i & 7u))) != 0u);
        if (!defined) continue;
        if (substreams) substreams[i].crc = seven_zip_read_u32_le(data + *position);
        if (count == 1u && out_single_crc)
            *out_single_crc = seven_zip_read_u32_le(data + *position);
        *position += 4u;
    }
    return 1;
}

static int seven_zip_parse_pack_info(const uint8_t *data, size_t size,
                                     size_t *position,
                                     QwSevenZipStreamInfo *info)
{
    uint64_t stream_count;
    int saw_size = 0;
    int saw_crc = 0;
    int saw_end = 0;
    if (*position >= size || data[(*position)++] != SEVEN_ZIP_ID_PACK_INFO ||
        !seven_zip_read_number(data, size, position, &info->pack_position) ||
        !seven_zip_read_number(data, size, position, &stream_count) ||
        stream_count != 1u) return 0;
    while (*position < size) {
        uint8_t property = data[(*position)++];
        if (property == SEVEN_ZIP_ID_END) {
            saw_end = 1;
            break;
        }
        if (property == SEVEN_ZIP_ID_SIZE) {
            if (saw_size || !seven_zip_read_number(data, size, position,
                                                   &info->pack_size)) return 0;
            saw_size = 1;
        } else if (property == SEVEN_ZIP_ID_CRC) {
            int defined = 0;
            if (saw_crc || !seven_zip_read_digests(
                    data, size, position, 1u, NULL, &defined,
                    &info->pack_crc)) return 0;
            info->has_pack_crc = defined;
            saw_crc = 1;
        } else {
            return 0;
        }
    }
    return saw_size && saw_end;
}

static int seven_zip_parse_folder_coder(const uint8_t *data, size_t size,
                                        size_t *position,
                                        QwSevenZipStreamInfo *info)
{
    uint64_t coder_count;
    QwSevenZipCoder parsed_coders[QW_SEVEN_ZIP_MAX_CODERS];
    size_t input_owner[QW_SEVEN_ZIP_MAX_CODERS];
    size_t output_to_input[QW_SEVEN_ZIP_MAX_CODERS];
    uint8_t input_is_bound[QW_SEVEN_ZIP_MAX_CODERS] = {0};
    uint8_t output_is_bound[QW_SEVEN_ZIP_MAX_CODERS] = {0};
    uint8_t visited[QW_SEVEN_ZIP_MAX_CODERS] = {0};
    size_t count;
    size_t packed_input = SIZE_MAX;
    size_t unpacked_output = SIZE_MAX;
    size_t current_coder;
    if (!seven_zip_read_number(data, size, position, &coder_count) ||
        !coder_count || coder_count > QW_SEVEN_ZIP_MAX_CODERS) return 0;
    count = (size_t)coder_count;
    for (size_t i = 0u; i < count; ++i) {
        uint8_t flags;
        size_t method_size;
        uint32_t method = 0u;
        uint64_t input_count = 1u;
        uint64_t output_count = 1u;
        uint64_t properties_size;
        if (*position >= size) return 0;
        flags = data[(*position)++];
        method_size = flags & 0x0fu;
        if (!method_size || method_size > 4u || (flags & 0xc0u) != 0u ||
            method_size > size - *position) return 0;
        for (size_t j = 0u; j < method_size; ++j)
            method = (method << 8) | data[(*position)++];
        if (flags & 0x10u) {
            if (!seven_zip_read_number(data, size, position, &input_count) ||
                !seven_zip_read_number(data, size, position, &output_count))
                return 0;
        }
        if (input_count != 1u || output_count != 1u) return 0;
        parsed_coders[i].method = method;
        parsed_coders[i].properties = NULL;
        parsed_coders[i].properties_size = 0u;
        if (flags & 0x20u) {
            if (!seven_zip_read_number(data, size, position,
                                      &properties_size) ||
                properties_size > (uint64_t)(size - *position)) return 0;
            parsed_coders[i].properties = data + *position;
            parsed_coders[i].properties_size = (size_t)properties_size;
            *position += (size_t)properties_size;
        }
        if (method == 0u && parsed_coders[i].properties_size != 0u) return 0;
        input_owner[i] = i;
    }
    for (size_t i = 0u; i + 1u < count; ++i) {
        uint64_t input_index;
        uint64_t output_index;
        if (!seven_zip_read_number(data, size, position, &input_index) ||
            !seven_zip_read_number(data, size, position, &output_index) ||
            input_index >= (uint64_t)count || output_index >= (uint64_t)count ||
            input_is_bound[(size_t)input_index] ||
            output_is_bound[(size_t)output_index]) return 0;
        input_is_bound[(size_t)input_index] = 1u;
        output_is_bound[(size_t)output_index] = 1u;
        output_to_input[(size_t)output_index] = (size_t)input_index;
    }
    for (size_t i = 0u; i < count; ++i) {
        if (!input_is_bound[i]) {
            if (packed_input != SIZE_MAX) return 0;
            packed_input = i;
        }
        if (!output_is_bound[i]) {
            if (unpacked_output != SIZE_MAX) return 0;
            unpacked_output = i;
        }
    }
    if (packed_input == SIZE_MAX || unpacked_output == SIZE_MAX) return 0;
    info->output_stream_count = count;
    info->unpacked_output_index = unpacked_output;
    current_coder = input_owner[packed_input];
    info->coder_count = 0u;
    while (current_coder != SIZE_MAX) {
        size_t output_index;
        if (current_coder >= count || visited[current_coder] ||
            info->coder_count >= count) return 0;
        visited[current_coder] = 1u;
        info->coders[info->coder_count++] = parsed_coders[current_coder];
        output_index = current_coder;
        if (!output_is_bound[output_index]) {
            if (output_index != unpacked_output) return 0;
            current_coder = SIZE_MAX;
        } else {
            current_coder = input_owner[output_to_input[output_index]];
        }
    }
    return info->coder_count == count;
}

static int seven_zip_parse_unpack_info(const uint8_t *data, size_t size,
                                       size_t *position,
                                       QwSevenZipStreamInfo *info)
{
    uint64_t folder_count;
    uint8_t external;
    int has_crc = 0;
    if (*position >= size || data[(*position)++] != SEVEN_ZIP_ID_UNPACK_INFO ||
        *position >= size || data[(*position)++] != SEVEN_ZIP_ID_FOLDER ||
        !seven_zip_read_number(data, size, position, &folder_count) ||
        folder_count != 1u || *position >= size) return 0;
    external = data[(*position)++];
    if (external != 0u || !seven_zip_parse_folder_coder(
            data, size, position, info) || *position >= size ||
        data[(*position)++] != SEVEN_ZIP_ID_CODERS_UNPACK_SIZE) return 0;
    for (size_t i = 0u; i < info->output_stream_count; ++i) {
        uint64_t unpack_size;
        if (!seven_zip_read_number(data, size, position, &unpack_size)) return 0;
        if (i == info->unpacked_output_index) info->unpack_size = unpack_size;
    }
    if (*position < size && data[*position] == SEVEN_ZIP_ID_CRC) {
        int defined = 0;
        ++*position;
        if (!seven_zip_read_digests(data, size, position, 1u, NULL, &defined,
                                    &info->folder_crc)) return 0;
        has_crc = defined;
    }
    if (*position >= size || data[(*position)++] != SEVEN_ZIP_ID_END ||
        !info->unpack_size) return 0;
    info->has_folder_crc = has_crc;
    return 1;
}

static int seven_zip_allocate_substreams(QwSevenZipStreamInfo *info,
                                         size_t count)
{
    if (!count || count > SEVEN_ZIP_FILE_COUNT_LIMIT ||
        count > SIZE_MAX / sizeof(*info->substreams)) return 0;
    info->substreams = (QwSevenZipSubstream *)calloc(
        count, sizeof(*info->substreams));
    if (!info->substreams) return 0;
    info->substream_count = count;
    return 1;
}

static int seven_zip_parse_substreams_info(const uint8_t *data, size_t size,
                                           size_t *position,
                                           QwSevenZipStreamInfo *info)
{
    size_t stream_count = 1u;
    int saw_count = 0;
    int saw_size = 0;
    int saw_crc = 0;
    int saw_end = 0;
    if (*position >= size ||
        data[(*position)++] != SEVEN_ZIP_ID_SUBSTREAMS_INFO) return 0;
    while (*position < size) {
        uint8_t property = data[(*position)++];
        if (property == SEVEN_ZIP_ID_END) {
            saw_end = 1;
            break;
        }
        if (property == SEVEN_ZIP_ID_NUM_UNPACK_STREAM) {
            uint64_t parsed_count;
            if (saw_count || !seven_zip_read_number(data, size, position,
                                                    &parsed_count) ||
                parsed_count > SEVEN_ZIP_FILE_COUNT_LIMIT ||
                parsed_count == 0u || info->substreams) return 0;
            stream_count = (size_t)parsed_count;
            saw_count = 1;
            if (!seven_zip_allocate_substreams(info, stream_count)) return 0;
        } else if (property == SEVEN_ZIP_ID_SIZE) {
            uint64_t size_sum = 0u;
            if (saw_size) return 0;
            if (!info->substreams &&
                !seven_zip_allocate_substreams(info, stream_count)) return 0;
            if (stream_count == 1u) {
                info->substreams[0].unpack_size = info->unpack_size;
            } else {
                for (size_t i = 0u; i + 1u < stream_count; ++i) {
                    if (!seven_zip_read_number(data, size, position,
                                              &info->substreams[i].unpack_size) ||
                        info->substreams[i].unpack_size > UINT64_MAX - size_sum)
                        return 0;
                    size_sum += info->substreams[i].unpack_size;
                }
                if (size_sum > info->unpack_size) return 0;
                info->substreams[stream_count - 1u].unpack_size =
                    info->unpack_size - size_sum;
            }
            saw_size = 1;
        } else if (property == SEVEN_ZIP_ID_CRC) {
            size_t digest_count;
            if (saw_crc) return 0;
            if (stream_count == 1u && info->has_folder_crc)
                digest_count = 0u;
            else
                digest_count = stream_count;
            if (!info->substreams &&
                !seven_zip_allocate_substreams(info, stream_count)) return 0;
            if (!seven_zip_read_digests(data, size, position, digest_count,
                                        info->substreams,
                                        NULL, NULL)) return 0;
            saw_crc = 1;
        } else {
            return 0;
        }
    }
    if (!saw_end) return 0;
    if (!info->substreams && !seven_zip_allocate_substreams(info, stream_count))
        return 0;
    if (stream_count == 1u && !saw_size)
        info->substreams[0].unpack_size = info->unpack_size;
    else if (stream_count > 1u && !saw_size)
        return 0;
    if (stream_count == 1u && info->has_folder_crc &&
        !info->substreams[0].has_crc) {
        info->substreams[0].has_crc = 1;
        info->substreams[0].crc = info->folder_crc;
    }
    return 1;
}

int qw_seven_zip_stream_info_parse(const uint8_t *data, size_t size,
                                   size_t *position,
                                   QwSevenZipStreamInfo *out_info)
{
    QwSevenZipStreamInfo info = {0};
    if (!data || !position || !out_info || *position >= size) return 0;
    *out_info = (QwSevenZipStreamInfo){0};
    if (!seven_zip_parse_pack_info(data, size, position, &info) ||
        !seven_zip_parse_unpack_info(data, size, position, &info)) goto error;
    if (*position < size && data[*position] == SEVEN_ZIP_ID_SUBSTREAMS_INFO) {
        if (!seven_zip_parse_substreams_info(data, size, position, &info))
            goto error;
    } else {
        if (!seven_zip_allocate_substreams(&info, 1u)) goto error;
        info.substreams[0].unpack_size = info.unpack_size;
        if (info.has_folder_crc) {
            info.substreams[0].has_crc = 1;
            info.substreams[0].crc = info.folder_crc;
        }
    }
    *out_info = info;
    return 1;
error:
    qw_seven_zip_stream_info_dispose(&info);
    return 0;
}

int qw_seven_zip_stream_info_decode(const uint8_t *archive,
                                    size_t archive_size,
                                    size_t next_header_offset,
                                    const QwSevenZipStreamInfo *info,
                                    uint8_t *decoded,
                                    size_t decoded_size)
{
    size_t pack_offset;
    const uint8_t *packed;
    uLong crc;
    if (!archive || !info || !decoded || !decoded_size ||
        info->unpack_size != (uint64_t)decoded_size ||
        info->unpack_size > (uint64_t)SEVEN_ZIP_STREAM_MEMORY_LIMIT ||
        info->pack_size > (uint64_t)SEVEN_ZIP_STREAM_MEMORY_LIMIT ||
        info->pack_position > (uint64_t)(SIZE_MAX - SEVEN_ZIP_START_HEADER_SIZE))
        return 0;
    pack_offset = SEVEN_ZIP_START_HEADER_SIZE + (size_t)info->pack_position;
    if (pack_offset > next_header_offset || pack_offset > archive_size ||
        info->pack_size > (uint64_t)(next_header_offset - pack_offset) ||
        info->pack_size > (uint64_t)(archive_size - pack_offset) ||
        info->pack_size > UINT_MAX) return 0;
    packed = archive + pack_offset;
    crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const Bytef *)packed, (uInt)info->pack_size);
    if (info->has_pack_crc && (uint32_t)crc != info->pack_crc) return 0;
    if (!qw_seven_zip_decode_chain(info->coders, info->coder_count, packed,
                                   (size_t)info->pack_size, decoded,
                                   decoded_size)) return 0;
    crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const Bytef *)decoded, (uInt)decoded_size);
    return !info->has_folder_crc || (uint32_t)crc == info->folder_crc;
}

void qw_seven_zip_stream_info_dispose(QwSevenZipStreamInfo *info)
{
    if (!info) return;
    free(info->substreams);
    *info = (QwSevenZipStreamInfo){0};
}
