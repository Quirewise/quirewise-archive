#include "rar4_parser.h"
#include "rar4_filename_parser.h"

#include "../../core/crc32.h"
#include "quirewise/status.h"

#include <stdlib.h>
#include <string.h>

enum {
    RAR4_SIGNATURE_SIZE = 7u,
    RAR4_COMMON_HEADER_SIZE = 7u,
    RAR4_FILE_HEADER_SIZE = 32u,
    RAR4_MAIN_HEADER = 0x73u,
    RAR4_FILE_HEADER = 0x74u,
    RAR4_END_HEADER = 0x7bu,
    RAR4_MAIN_VOLUME = 0x0001u,
    RAR4_MAIN_SOLID = 0x0008u,
    RAR4_MAIN_NEW_NUMBERING = 0x0010u,
    RAR4_MAIN_PASSWORD = 0x0080u,
    RAR4_MAIN_FIRST_VOLUME = 0x0100u,
    RAR4_MAIN_ENCRYPT_VERSION = 0x0200u,
    RAR4_FILE_SPLIT_BEFORE = 0x0001u,
    RAR4_FILE_SPLIT_AFTER = 0x0002u,
    RAR4_FILE_PASSWORD = 0x0004u,
    RAR4_FILE_SOLID = 0x0010u,
    RAR4_FILE_DIRECTORY = 0x00e0u,
    RAR4_FILE_LARGE = 0x0100u,
    RAR4_FILE_UNICODE = 0x0200u,
    RAR4_FILE_SALT = 0x0400u,
    RAR4_FILE_EXT_TIME = 0x1000u,
    RAR4_FILE_EXT_FLAGS = 0x2000u,
    RAR4_SKIP_IF_UNKNOWN = 0x4000u,
    RAR4_LONG_BLOCK = 0x8000u,
    RAR4_END_NEXT_VOLUME = 0x0001u,
    RAR4_END_FLAG_MASK = 0x000fu,
    RAR4_METHOD_STORE = 0x30u
};

static const uint8_t rar4_signature[RAR4_SIGNATURE_SIZE] = {
    0x52u, 0x61u, 0x72u, 0x21u, 0x1au, 0x07u, 0x00u
};

static uint16_t rar4_read_u16_le(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] |
                      ((uint16_t)bytes[1] << 8u));
}

static uint32_t rar4_read_u32_le(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8u) |
           ((uint32_t)bytes[2] << 16u) |
           ((uint32_t)bytes[3] << 24u);
}

static int rar4_header_crc_valid(const uint8_t *bytes,
                                 size_t position,
                                 size_t block_size)
{
    uint16_t expected;
    uint16_t actual;

    if (!bytes || block_size < RAR4_COMMON_HEADER_SIZE) return 0;
    expected = rar4_read_u16_le(bytes + position);
    actual = (uint16_t)(qw_crc32_ieee(bytes + position + 2u,
                                      block_size - 2u) & 0xffffu);
    return actual == expected;
}

static int rar4_parse_file(const uint8_t *bytes,
                           size_t size,
                           size_t position,
                           size_t header_size,
                           uint16_t flags,
                           uint16_t archive_flags,
                           const QwRarLimits *limits,
                           size_t *entry_count,
                           uint64_t *total_uncompressed,
                           QwRarEntryFn visit_entry,
                           void *context,
                           size_t *next_position)
{
    const uint8_t *header = bytes + position;
    const uint8_t *name;
    const uint8_t *entry_name;
    const uint8_t *payload;
    uint8_t *decoded_name = NULL;
    size_t header_end;
    size_t cursor;
    size_t name_size;
    size_t entry_name_size;
    size_t payload_size;
    uint64_t packed_size;
    uint64_t unpacked_size;
    uint32_t data_crc32;
    uint16_t stored_name_size;
    uint8_t method;
    int is_directory;
    int rc;

    if (header_size < RAR4_FILE_HEADER_SIZE ||
        header_size > size - position) {
        return QW_STATUS_ERR_FORMAT;
    }
    if (flags & (RAR4_FILE_SPLIT_BEFORE | RAR4_FILE_SPLIT_AFTER |
                 RAR4_FILE_PASSWORD | RAR4_FILE_EXT_FLAGS)) {
        return QW_STATUS_ERR_UNSUPPORTED;
    }
    if (*entry_count >= limits->max_entries) return QW_STATUS_ERR_RESOURCE_LIMIT;
    ++*entry_count;

    packed_size = rar4_read_u32_le(header + 7u);
    unpacked_size = rar4_read_u32_le(header + 11u);
    data_crc32 = rar4_read_u32_le(header + 16u);
    method = header[25u];
    stored_name_size = rar4_read_u16_le(header + 26u);
    is_directory = (flags & RAR4_FILE_DIRECTORY) == RAR4_FILE_DIRECTORY;
    cursor = position + RAR4_FILE_HEADER_SIZE;

    if (flags & RAR4_FILE_LARGE) {
        uint32_t high_packed;
        uint32_t high_unpacked;
        if (header_size - RAR4_FILE_HEADER_SIZE < 8u)
            return QW_STATUS_ERR_FORMAT;
        high_packed = rar4_read_u32_le(bytes + cursor);
        high_unpacked = rar4_read_u32_le(bytes + cursor + 4u);
        packed_size |= (uint64_t)high_packed << 32u;
        unpacked_size |= (uint64_t)high_unpacked << 32u;
        cursor += 8u;
    }
    if ((size_t)stored_name_size > position + header_size - cursor)
        return QW_STATUS_ERR_FORMAT;
    name = bytes + cursor;
    name_size = (size_t)stored_name_size;
    if (name_size == 0u) return QW_STATUS_ERR_FORMAT;
    cursor += name_size;
    if (flags & RAR4_FILE_SALT) {
        if (cursor > position + header_size ||
            position + header_size - cursor < 8u) {
            return QW_STATUS_ERR_FORMAT;
        }
        cursor += 8u;
    }
    if ((flags & RAR4_FILE_EXT_TIME) &&
        (cursor > position + header_size ||
         position + header_size - cursor < 2u)) {
        return QW_STATUS_ERR_FORMAT;
    }
    header_end = position + header_size;
    if (header_end > size) return QW_STATUS_ERR_FORMAT;
    if (!rar4_header_crc_valid(bytes, position, header_size))
        return QW_STATUS_ERR_FORMAT;

    if (is_directory) {
        if (packed_size != 0u || unpacked_size != 0u)
            return QW_STATUS_ERR_FORMAT;
        rc = qw_rar4_decode_entry_name(name, name_size,
                                       (flags & RAR4_FILE_UNICODE) != 0u,
                                       &entry_name, &entry_name_size,
                                       &decoded_name);
        if (rc != QW_STATUS_OK) return rc;
        {
            QwRarEntry entry;
            memset(&entry, 0, sizeof(entry));
            entry.name = entry_name;
            entry.name_size = entry_name_size;
            entry.archive_flags = archive_flags;
            entry.format_flags = flags;
            entry.compression_info = method;
            entry.compression_method =
                method >= RAR4_METHOD_STORE && method <= 0x35u
                    ? (uint32_t)(method - RAR4_METHOD_STORE)
                    : UINT32_MAX;
            entry.format_version = 4u;
            entry.compression_version = header[24u];
            entry.is_directory = 1;
            entry.is_solid = 0;
            rc = visit_entry(context, &entry);
        }
        free(decoded_name);
        if (rc != QW_STATUS_OK) return rc;
        *next_position = header_end;
        return QW_STATUS_OK;
    }
    if (method == RAR4_METHOD_STORE && packed_size != unpacked_size)
        return QW_STATUS_ERR_FORMAT;
    if (unpacked_size > limits->max_entry_bytes ||
        *total_uncompressed > limits->max_total_bytes ||
        unpacked_size > limits->max_total_bytes - *total_uncompressed) {
        return QW_STATUS_ERR_RESOURCE_LIMIT;
    }
    if (packed_size > (uint64_t)(size - header_end))
        return QW_STATUS_ERR_FORMAT;
    payload_size = (size_t)packed_size;
    payload = bytes + header_end;
    if (method == RAR4_METHOD_STORE &&
        qw_crc32_ieee(payload, payload_size) != data_crc32)
        return QW_STATUS_ERR_FORMAT;
    if (unpacked_size > UINT64_MAX - *total_uncompressed)
        return QW_STATUS_ERR_FORMAT;

    rc = qw_rar4_decode_entry_name(name, name_size,
                                   (flags & RAR4_FILE_UNICODE) != 0u,
                                   &entry_name, &entry_name_size,
                                   &decoded_name);
    if (rc != QW_STATUS_OK) return rc;
    *total_uncompressed += unpacked_size;

    {
        QwRarEntry entry;
        memset(&entry, 0, sizeof(entry));
        entry.name = entry_name;
        entry.name_size = entry_name_size;
        entry.packed_data = payload;
        entry.packed_size = payload_size;
        entry.uncompressed_size = unpacked_size;
        entry.data_crc32 = data_crc32;
        entry.archive_flags = archive_flags;
        entry.format_flags = flags;
        entry.compression_info = method;
        entry.compression_method =
            method >= RAR4_METHOD_STORE && method <= 0x35u
                ? (uint32_t)(method - RAR4_METHOD_STORE)
                : UINT32_MAX;
        entry.format_version = 4u;
        entry.compression_version = header[24u];
        entry.is_directory = 0;
        entry.is_stored = method == RAR4_METHOD_STORE;
        entry.is_solid = header[24u] < 20u
            ? ((archive_flags & RAR4_MAIN_SOLID) != 0u && *entry_count > 1u)
            : ((flags & RAR4_FILE_SOLID) != 0u);
        entry.has_data_crc32 = 1;
        rc = visit_entry(context, &entry);
    }
    free(decoded_name);
    if (rc != QW_STATUS_OK) return rc;
    *next_position = header_end + payload_size;
    return QW_STATUS_OK;
}

int qw_rar4_parse_entries(const uint8_t *bytes,
                          size_t size,
                          const QwRarLimits *limits,
                          QwRarEntryFn visit_entry,
                          void *context)
{
    size_t position = RAR4_SIGNATURE_SIZE;
    size_t entry_count = 0u;
    uint64_t total_uncompressed = 0u;
    uint16_t archive_flags = 0u;
    int main_seen = 0;
    int end_seen = 0;

    if (!bytes || !limits || !visit_entry) return QW_STATUS_ERR_INVALID_ARGUMENT;
    if (size < RAR4_SIGNATURE_SIZE ||
        memcmp(bytes, rar4_signature, RAR4_SIGNATURE_SIZE) != 0) {
        return QW_STATUS_ERR_UNSUPPORTED;
    }
    if (!limits->max_entries || !limits->max_entry_bytes ||
        !limits->max_total_bytes) {
        return QW_STATUS_ERR_RESOURCE_LIMIT;
    }

    while (position < size) {
        size_t header_size;
        size_t header_end;
        size_t next_position;
        uint8_t header_type;
        uint16_t flags;
        int rc;

        if (size - position < RAR4_COMMON_HEADER_SIZE)
            return QW_STATUS_ERR_FORMAT;
        header_type = bytes[position + 2u];
        flags = rar4_read_u16_le(bytes + position + 3u);
        header_size = (size_t)rar4_read_u16_le(bytes + position + 5u);
        if (header_size < RAR4_COMMON_HEADER_SIZE ||
            header_size > size - position) {
            return QW_STATUS_ERR_FORMAT;
        }
        header_end = position + header_size;

        if (header_type == RAR4_MAIN_HEADER) {
            if (main_seen || header_size < 13u) return QW_STATUS_ERR_FORMAT;
            if (flags & (RAR4_MAIN_VOLUME |
                         RAR4_MAIN_NEW_NUMBERING | RAR4_MAIN_PASSWORD |
                         RAR4_MAIN_FIRST_VOLUME | RAR4_MAIN_ENCRYPT_VERSION)) {
                return QW_STATUS_ERR_UNSUPPORTED;
            }
            if (!rar4_header_crc_valid(bytes, position, header_size))
                return QW_STATUS_ERR_FORMAT;
            archive_flags = flags;
            main_seen = 1;
            position = header_end;
            continue;
        }
        if (!main_seen) return QW_STATUS_ERR_FORMAT;

        if (header_type == RAR4_FILE_HEADER) {
            rc = rar4_parse_file(bytes, size, position, header_size, flags,
                                 archive_flags,
                                 limits, &entry_count, &total_uncompressed,
                                 visit_entry, context, &next_position);
            if (rc != QW_STATUS_OK) return rc;
            position = next_position;
            continue;
        }

        if (flags & RAR4_LONG_BLOCK) {
            uint32_t add_size;
            size_t block_size;
            if (header_size < RAR4_COMMON_HEADER_SIZE + 4u)
                return QW_STATUS_ERR_FORMAT;
            add_size = rar4_read_u32_le(bytes + position + 7u);
            if ((uint64_t)add_size > (uint64_t)(size - header_end))
                return QW_STATUS_ERR_FORMAT;
            block_size = header_size + (size_t)add_size;
            if (block_size > size - position) return QW_STATUS_ERR_FORMAT;
            if (!rar4_header_crc_valid(bytes, position, block_size))
                return QW_STATUS_ERR_FORMAT;
            next_position = position + block_size;
        } else {
            if (!rar4_header_crc_valid(bytes, position, header_size))
                return QW_STATUS_ERR_FORMAT;
            next_position = header_end;
        }

        if (header_type == RAR4_END_HEADER) {
            if (flags & RAR4_END_NEXT_VOLUME) return QW_STATUS_ERR_UNSUPPORTED;
            if (flags & RAR4_END_FLAG_MASK) return QW_STATUS_ERR_UNSUPPORTED;
            if (next_position != size) return QW_STATUS_ERR_FORMAT;
            position = next_position;
            end_seen = 1;
            break;
        }
        if (header_type != 0x75u && header_type != 0x76u &&
            header_type != 0x77u && header_type != 0x78u &&
            header_type != 0x79u && header_type != 0x7au &&
            (flags & RAR4_SKIP_IF_UNKNOWN) == 0u) {
            return QW_STATUS_ERR_UNSUPPORTED;
        }
        position = next_position;
    }

    if (!main_seen || (position != size && !end_seen))
        return QW_STATUS_ERR_FORMAT;
    return QW_STATUS_OK;
}
