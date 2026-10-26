#include "seven_zip_files_info.h"

#include "../image/image_internal.h"

#include <stdlib.h>
#include <string.h>

enum {
    SEVEN_ZIP_FILE_COUNT_LIMIT = 1000000u,
    SEVEN_ZIP_ID_FILES_INFO = 0x05u,
    SEVEN_ZIP_ID_NAME = 0x11u
};

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

static int seven_zip_bit(const uint8_t *bits, size_t index)
{
    return bits &&
           (bits[index >> 3] & (uint8_t)(1u << (index & 7u))) != 0u;
}

static int seven_zip_bit_vector_valid(const uint8_t *bits, size_t size,
                                      size_t bit_count)
{
    size_t required = (bit_count + 7u) / 8u;
    if (size != required || (required && !bits)) return 0;
    if (bit_count % 8u) {
        uint8_t unused_mask = (uint8_t)(0xffu << (bit_count % 8u));
        if (bits[required - 1u] & unused_mask) return 0;
    }
    return 1;
}

static size_t seven_zip_append_utf8(uint32_t codepoint, char *output)
{
    if (codepoint < 0x80u) {
        output[0] = (char)codepoint;
        return 1u;
    }
    if (codepoint < 0x800u) {
        output[0] = (char)(0xc0u | (codepoint >> 6));
        output[1] = (char)(0x80u | (codepoint & 0x3fu));
        return 2u;
    }
    if (codepoint < 0x10000u) {
        output[0] = (char)(0xe0u | (codepoint >> 12));
        output[1] = (char)(0x80u | ((codepoint >> 6) & 0x3fu));
        output[2] = (char)(0x80u | (codepoint & 0x3fu));
        return 3u;
    }
    output[0] = (char)(0xf0u | (codepoint >> 18));
    output[1] = (char)(0x80u | ((codepoint >> 12) & 0x3fu));
    output[2] = (char)(0x80u | ((codepoint >> 6) & 0x3fu));
    output[3] = (char)(0x80u | (codepoint & 0x3fu));
    return 4u;
}

static uint16_t seven_zip_read_u16_le(const uint8_t *data)
{
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static int seven_zip_parse_names(const uint8_t *data, size_t size,
                                 size_t file_count,
                                 QwSevenZipFilesInfo *info)
{
    size_t position = 1u;
    if (!data || !size || data[0] != 0u) return 0;
    if (file_count > SIZE_MAX / sizeof(*info->names)) return 0;
    if (file_count) {
        info->names = (char **)calloc(file_count, sizeof(*info->names));
        if (!info->names) return 0;
    }
    for (size_t file = 0u; file < file_count; ++file) {
        size_t max_units;
        size_t capacity;
        size_t written = 0u;
        char *name;
        int terminated = 0;
        if ((size - position) % 2u) return 0;
        max_units = (size - position) / 2u;
        if (max_units > (SIZE_MAX - 1u) / 3u) return 0;
        capacity = max_units * 3u + 1u;
        name = (char *)malloc(capacity);
        if (!name) return 0;
        while (position + 1u < size) {
            uint16_t first = seven_zip_read_u16_le(data + position);
            uint32_t codepoint = first;
            position += 2u;
            if (!first) {
                terminated = 1;
                break;
            }
            if (first >= 0xd800u && first <= 0xdbffu) {
                uint16_t second;
                if (position + 1u >= size) break;
                second = seven_zip_read_u16_le(data + position);
                if (second < 0xdc00u || second > 0xdfffu) break;
                position += 2u;
                codepoint = 0x10000u +
                    (((uint32_t)first - 0xd800u) << 10) +
                    ((uint32_t)second - 0xdc00u);
            } else if (first >= 0xdc00u && first <= 0xdfffu) {
                break;
            }
            written += seven_zip_append_utf8(codepoint, name + written);
        }
        if (!terminated) {
            free(name);
            return 0;
        }
        name[written] = '\0';
        info->names[file] = name;
    }
    return position == size;
}

void qw_seven_zip_files_info_dispose(QwSevenZipFilesInfo *info)
{
    if (!info) return;
    if (info->names) {
        for (size_t i = 0u; i < info->file_count; ++i) free(info->names[i]);
    }
    free(info->names);
    *info = (QwSevenZipFilesInfo){0};
}

int qw_seven_zip_files_info_parse(const uint8_t *header, size_t size,
                                  size_t start,
                                  QwSevenZipFilesInfo *out_info)
{
    uint64_t file_count;
    size_t position;
    int saw_names = 0;
    int saw_start_pos = 0;
    uint8_t seen_properties[9] = {0};
    if (!out_info) return 0;
    *out_info = (QwSevenZipFilesInfo){0};
    if (!header || start >= size || header[start] != SEVEN_ZIP_ID_FILES_INFO)
        return 0;
    position = start + 1u;
    if (!seven_zip_read_number(header, size, &position, &file_count) ||
        file_count > SEVEN_ZIP_FILE_COUNT_LIMIT) return 0;
    out_info->file_count = (size_t)file_count;
    while (position < size) {
        uint8_t property = header[position++];
        uint64_t property_size;
        if (property == 0u) break;
        if (property >= 0x0eu && property <= 0x16u) {
            if (seen_properties[property - 0x0eu]) goto error;
            seen_properties[property - 0x0eu] = 1u;
        } else if (property == 0x18u) {
            if (saw_start_pos) goto error;
            saw_start_pos = 1;
        } else if (property != 0x19u) {
            goto error;
        }
        if (!seven_zip_read_number(header, size, &position, &property_size) ||
            property_size > (uint64_t)(size - position)) goto error;
        if (property == SEVEN_ZIP_ID_NAME) {
            if (saw_names || !seven_zip_parse_names(
                    header + position, (size_t)property_size,
                    out_info->file_count, out_info)) goto error;
            saw_names = 1;
        } else if (property == 0x0eu) {
            size_t expected = (out_info->file_count + 7u) / 8u;
            if (property_size != (uint64_t)expected) goto error;
            out_info->empty_stream_bits = header + position;
            out_info->empty_stream_size = (size_t)property_size;
            out_info->has_empty_stream = 1;
        } else if (property == 0x0fu) {
            out_info->empty_file_bits = header + position;
            out_info->empty_file_size = (size_t)property_size;
            out_info->has_empty_file = 1;
        } else if (property == 0x10u) {
            out_info->anti_bits = header + position;
            out_info->anti_size = (size_t)property_size;
            out_info->has_anti = 1;
        } else if (property == 0x19u) {
            for (size_t i = 0u; i < (size_t)property_size; ++i)
                if (header[position + i] != 0u) goto error;
        }
        position += (size_t)property_size;
    }
    if (position >= size || header[position++] != 0u || position != size ||
        (file_count != 0u && (!saw_names || !out_info->names)) ||
        ((out_info->has_empty_file || out_info->has_anti) &&
         !out_info->has_empty_stream)) goto error;
    if (out_info->has_empty_stream) {
        if (!seven_zip_bit_vector_valid(out_info->empty_stream_bits,
                                        out_info->empty_stream_size,
                                        out_info->file_count)) goto error;
        for (size_t i = 0u; i < out_info->file_count; ++i)
            if (seven_zip_bit(out_info->empty_stream_bits, i))
                ++out_info->empty_stream_count;
        if (out_info->has_empty_file &&
            !seven_zip_bit_vector_valid(out_info->empty_file_bits,
                                        out_info->empty_file_size,
                                        out_info->empty_stream_count))
            goto error;
        if (out_info->has_anti &&
            !seven_zip_bit_vector_valid(out_info->anti_bits,
                                        out_info->anti_size,
                                        out_info->empty_stream_count))
            goto error;
    }
    return 1;
error:
    qw_seven_zip_files_info_dispose(out_info);
    return 0;
}

#ifndef QUIREWISE_STANDALONE_SEVEN_ZIP
int qw_seven_zip_files_info_has_image(const QwSevenZipFilesInfo *info)
{
    size_t empty_index = 0u;
    if (!info) return 0;
    for (size_t i = 0u; i < info->file_count; ++i) {
        int has_stream;
        int is_directory;
        int is_anti;
        qw_seven_zip_files_info_entry_state(
            info, i, &empty_index, &has_stream, &is_directory, &is_anti);
        if (!info->names || !info->names[i]) continue;
        if (qw_image_name_is_supported(info->names[i]) &&
            (has_stream || (!is_directory && !is_anti))) return 1;
    }
    return 0;
}
#endif

void qw_seven_zip_files_info_entry_state(const QwSevenZipFilesInfo *info,
                                        size_t file_index,
                                        size_t *empty_index,
                                        int *out_has_stream,
                                        int *out_is_directory,
                                        int *out_is_anti)
{
    size_t local_empty_index = 0u;
    int has_stream = 1;
    int is_directory = 0;
    int is_anti = 0;
    if (!info || file_index >= info->file_count) goto done;
    if (info->has_empty_stream &&
        seven_zip_bit(info->empty_stream_bits, file_index)) {
        size_t index = empty_index ? *empty_index : 0u;
        has_stream = 0;
        is_directory = !info->has_empty_file ||
            !seven_zip_bit(info->empty_file_bits, index);
        is_anti = info->has_anti && seven_zip_bit(info->anti_bits, index);
        local_empty_index = index + 1u;
    }
done:
    if (empty_index) {
        if (local_empty_index) *empty_index = local_empty_index;
    }
    if (out_has_stream) *out_has_stream = has_stream;
    if (out_is_directory) *out_is_directory = is_directory;
    if (out_is_anti) *out_is_anti = is_anti;
}
