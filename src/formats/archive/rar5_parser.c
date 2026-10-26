#include "rar5_parser.h"

#include "../../core/byte_utils.h"
#include "../../core/crc32.h"
#include "quirewise/status.h"

#include <string.h>

enum {
    RAR5_SIGNATURE_SIZE = 8u,
    RAR5_HEADER_MAX_SIZE = 2u * 1024u * 1024u,
    RAR5_HEADER_MAX_VINT_BYTES = 3u,
    RAR5_HEADER_FLAG_EXTRA = 0x0001u,
    RAR5_HEADER_FLAG_DATA = 0x0002u,
    RAR5_HEADER_FLAG_UNKNOWN_TYPE_SKIP = 0x0004u,
    RAR5_HEADER_FLAG_SPLIT_BEFORE = 0x0008u,
    RAR5_HEADER_FLAG_SPLIT_AFTER = 0x0010u,
    RAR5_HEADER_FLAG_DEPENDS_ON_PREVIOUS = 0x0020u,
    RAR5_HEADER_FLAG_PRESERVE_CHILD = 0x0040u,
    RAR5_FILE_FLAG_DIRECTORY = 0x0001u,
    RAR5_FILE_FLAG_MTIME = 0x0002u,
    RAR5_FILE_FLAG_CRC32 = 0x0004u,
    RAR5_FILE_FLAG_UNKNOWN_SIZE = 0x0008u,
    RAR5_FILE_FLAGS_MASK = 0x000fu,
    RAR5_MAIN_FLAG_VOLUME = 0x0001u,
    RAR5_MAIN_FLAG_VOLUME_NUMBER = 0x0002u,
    RAR5_MAIN_FLAG_SOLID = 0x0004u,
    RAR5_EXTRA_FILE_ENCRYPTION = 1u,
    RAR5_HEADER_MAIN = 1u,
    RAR5_HEADER_FILE = 2u,
    RAR5_HEADER_SERVICE = 3u,
    RAR5_HEADER_ENCRYPTION = 4u,
    RAR5_HEADER_END = 5u
};

static const uint8_t rar5_signature[RAR5_SIGNATURE_SIZE] = {
    0x52u, 0x61u, 0x72u, 0x21u, 0x1au, 0x07u, 0x01u, 0x00u
};

static int rar5_read_vint(const uint8_t *bytes,
                          size_t end,
                          size_t *position,
                          uint64_t *value)
{
    uint64_t result = 0u;
    unsigned int shift = 0u;
    unsigned int index;

    if (!bytes || !position || !value) return 0;
    for (index = 0u; index < 10u; ++index) {
        uint8_t byte;
        uint64_t payload;

        if (*position >= end) return 0;
        byte = bytes[(*position)++];
        payload = (uint64_t)(byte & 0x7fu);
        if (shift >= 64u || payload > (UINT64_MAX >> shift)) return 0;
        result |= payload << shift;
        if ((byte & 0x80u) == 0u) {
            *value = result;
            return 1;
        }
        shift += 7u;
    }
    return 0;
}

static int rar5_read_u32(const uint8_t *bytes,
                         size_t end,
                         size_t *position,
                         uint32_t *value)
{
    if (!bytes || !position || !value || *position > end ||
        end - *position < 4u) {
        return 0;
    }
    *value = qw_read_u32_le(bytes + *position);
    *position += 4u;
    return 1;
}

static int rar5_validate_extra_area(const uint8_t *bytes,
                                    size_t begin,
                                    size_t end,
                                    int file_or_service)
{
    size_t position = begin;

    while (position < end) {
        uint64_t record_size;
        uint64_t record_type;
        size_t record_end;

        if (!rar5_read_vint(bytes, end, &position, &record_size) ||
            record_size == 0u || record_size > (uint64_t)(end - position)) {
            return QW_STATUS_ERR_FORMAT;
        }
        record_end = position + (size_t)record_size;
        if (!rar5_read_vint(bytes, record_end, &position, &record_type))
            return QW_STATUS_ERR_FORMAT;
        if (file_or_service &&
            (record_type == RAR5_EXTRA_FILE_ENCRYPTION ||
             record_type == 2u || record_type == 5u)) {
            return QW_STATUS_ERR_UNSUPPORTED;
        }
        position = record_end;
    }
    return position == end ? QW_STATUS_OK : QW_STATUS_ERR_FORMAT;
}

static int rar5_header_extra_bounds(size_t body_position,
                                    size_t header_end,
                                    uint64_t extra_size,
                                    size_t *extra_begin)
{
    if (!extra_begin || body_position > header_end ||
        extra_size > (uint64_t)header_end ||
        extra_size > (uint64_t)(header_end - body_position)) {
        return 0;
    }
    *extra_begin = header_end - (size_t)extra_size;
    return *extra_begin >= body_position;
}

int qw_rar5_parse_entries(const uint8_t *bytes,
                          size_t size,
                          const QwRarLimits *limits,
                          QwRarEntryFn visit_entry,
                          void *context)
{
    size_t position = RAR5_SIGNATURE_SIZE;
    size_t entry_count = 0u;
    uint64_t total_uncompressed = 0u;
    uint64_t archive_flags = 0u;
    int main_seen = 0;
    int end_seen = 0;

    if (!bytes || !limits || !visit_entry) return QW_STATUS_ERR_INVALID_ARGUMENT;
    if (size < RAR5_SIGNATURE_SIZE ||
        memcmp(bytes, rar5_signature, RAR5_SIGNATURE_SIZE) != 0) {
        return QW_STATUS_ERR_UNSUPPORTED;
    }
    if (!limits->max_entries || !limits->max_entry_bytes ||
        !limits->max_total_bytes) {
        return QW_STATUS_ERR_RESOURCE_LIMIT;
    }

    while (position < size) {
        size_t crc_start;
        size_t body_position;
        size_t header_end;
        size_t extra_begin;
        size_t next_position;
        size_t header_size_vint_bytes;
        uint32_t expected_header_crc;
        uint64_t header_size;
        uint64_t header_type;
        uint64_t header_flags;
        uint64_t extra_size = 0u;
        uint64_t data_size = 0u;
        int has_extra;
        int has_data;
        int rc;

        if (size - position < 5u) return QW_STATUS_ERR_FORMAT;
        expected_header_crc = qw_read_u32_le(bytes + position);
        crc_start = position + 4u;
        body_position = crc_start;
        if (!rar5_read_vint(bytes, size, &body_position, &header_size))
            return QW_STATUS_ERR_FORMAT;
        header_size_vint_bytes = body_position - crc_start;
        if (header_size_vint_bytes > RAR5_HEADER_MAX_VINT_BYTES ||
            header_size < 2u || header_size > RAR5_HEADER_MAX_SIZE ||
            header_size > (uint64_t)(size - body_position)) {
            return QW_STATUS_ERR_FORMAT;
        }
        header_end = body_position + (size_t)header_size;
        if (qw_crc32_ieee(bytes + crc_start, header_end - crc_start) !=
            expected_header_crc) {
            return QW_STATUS_ERR_FORMAT;
        }
        if (!rar5_read_vint(bytes, header_end, &body_position, &header_type) ||
            !rar5_read_vint(bytes, header_end, &body_position, &header_flags)) {
            return QW_STATUS_ERR_FORMAT;
        }
        if ((header_flags & ~UINT64_C(0x7f)) != 0u)
            return QW_STATUS_ERR_UNSUPPORTED;
        if (header_flags & (RAR5_HEADER_FLAG_SPLIT_BEFORE |
                            RAR5_HEADER_FLAG_SPLIT_AFTER |
                            RAR5_HEADER_FLAG_DEPENDS_ON_PREVIOUS)) {
            return QW_STATUS_ERR_UNSUPPORTED;
        }
        has_extra = (header_flags & RAR5_HEADER_FLAG_EXTRA) != 0u;
        has_data = (header_flags & RAR5_HEADER_FLAG_DATA) != 0u;
        if (has_extra &&
            !rar5_read_vint(bytes, header_end, &body_position, &extra_size)) {
            return QW_STATUS_ERR_FORMAT;
        }
        if (has_data &&
            !rar5_read_vint(bytes, header_end, &body_position, &data_size)) {
            return QW_STATUS_ERR_FORMAT;
        }
        if (data_size > (uint64_t)(size - header_end))
            return QW_STATUS_ERR_FORMAT;
        next_position = header_end + (size_t)data_size;

        if (header_type == RAR5_HEADER_ENCRYPTION)
            return QW_STATUS_ERR_UNSUPPORTED;
        if (header_type == RAR5_HEADER_MAIN) {
            if (main_seen || has_data ||
                !rar5_read_vint(bytes, header_end, &body_position,
                                &archive_flags)) {
                return QW_STATUS_ERR_FORMAT;
            }
            if (archive_flags & (RAR5_MAIN_FLAG_VOLUME |
                                 RAR5_MAIN_FLAG_VOLUME_NUMBER)) {
                return QW_STATUS_ERR_UNSUPPORTED;
            }
            if (archive_flags & ~UINT64_C(0x1f))
                return QW_STATUS_ERR_UNSUPPORTED;
            if (archive_flags & RAR5_MAIN_FLAG_VOLUME_NUMBER) {
                uint64_t volume_number;
                if (!rar5_read_vint(bytes, header_end, &body_position,
                                    &volume_number)) {
                    return QW_STATUS_ERR_FORMAT;
                }
                (void)volume_number;
                return QW_STATUS_ERR_UNSUPPORTED;
            }
            if (!rar5_header_extra_bounds(body_position, header_end,
                                          extra_size, &extra_begin)) {
                return QW_STATUS_ERR_FORMAT;
            }
            if (has_extra) {
                rc = rar5_validate_extra_area(bytes, extra_begin, header_end, 0);
                if (rc != QW_STATUS_OK) return rc;
            } else if (body_position != header_end) {
                return QW_STATUS_ERR_FORMAT;
            }
            main_seen = 1;
        } else if (header_type == RAR5_HEADER_FILE ||
                   header_type == RAR5_HEADER_SERVICE) {
            uint64_t file_flags;
            uint64_t unpacked_size;
            uint64_t attributes;
            uint64_t compression_info = 0u;
            uint64_t host_os;
            uint64_t name_size;
            uint32_t data_crc32 = 0u;
            const uint8_t *name;
            const uint8_t *payload;
            size_t payload_size;
            int is_file = header_type == RAR5_HEADER_FILE;
            int is_directory;
            int has_crc32;

            if (!main_seen || entry_count >= limits->max_entries)
                return !main_seen ? QW_STATUS_ERR_FORMAT : QW_STATUS_ERR_RESOURCE_LIMIT;
            ++entry_count;
            if (!rar5_read_vint(bytes, header_end, &body_position,
                                &file_flags) ||
                !rar5_read_vint(bytes, header_end, &body_position,
                                &unpacked_size) ||
                !rar5_read_vint(bytes, header_end, &body_position,
                                &attributes)) {
                return QW_STATUS_ERR_FORMAT;
            }
            (void)attributes;
            if ((file_flags & ~(uint64_t)RAR5_FILE_FLAGS_MASK) != 0u)
                return QW_STATUS_ERR_UNSUPPORTED;
            if (file_flags & RAR5_FILE_FLAG_MTIME) {
                uint32_t mtime;
                if (!rar5_read_u32(bytes, header_end, &body_position, &mtime))
                    return QW_STATUS_ERR_FORMAT;
            }
            has_crc32 = (file_flags & RAR5_FILE_FLAG_CRC32) != 0u;
            if (has_crc32 &&
                !rar5_read_u32(bytes, header_end, &body_position, &data_crc32)) {
                return QW_STATUS_ERR_FORMAT;
            }
            if (file_flags & RAR5_FILE_FLAG_UNKNOWN_SIZE)
                return QW_STATUS_ERR_UNSUPPORTED;
            if (is_file &&
                !rar5_read_vint(bytes, header_end, &body_position,
                                &compression_info)) {
                return QW_STATUS_ERR_FORMAT;
            }
            if (!rar5_read_vint(bytes, header_end, &body_position, &host_os) ||
                !rar5_read_vint(bytes, header_end, &body_position, &name_size) ||
                name_size > (uint64_t)(header_end - body_position)) {
                return QW_STATUS_ERR_FORMAT;
            }
            (void)host_os;
            name = bytes + body_position;
            if (name_size && memchr(name, 0, (size_t)name_size) != NULL)
                return QW_STATUS_ERR_FORMAT;
            if (is_file && name_size == 0u) return QW_STATUS_ERR_FORMAT;
            body_position += (size_t)name_size;
            if (!rar5_header_extra_bounds(body_position, header_end,
                                          extra_size, &extra_begin)) {
                return QW_STATUS_ERR_FORMAT;
            }
            if (has_extra) {
                rc = rar5_validate_extra_area(bytes, extra_begin, header_end, 1);
                if (rc != QW_STATUS_OK) return rc;
            } else if (body_position != header_end) {
                return QW_STATUS_ERR_FORMAT;
            }

            is_directory = (file_flags & RAR5_FILE_FLAG_DIRECTORY) != 0u;
            if (is_file && !is_directory) {
                uint32_t compression_method =
                    (uint32_t)((compression_info & UINT64_C(0x0380)) >> 7u);
                uint64_t compression_version = compression_info & 0x3fu;
                int is_stored = compression_method == 0u &&
                                compression_version <= 1u;

                if (unpacked_size > limits->max_entry_bytes ||
                    total_uncompressed > limits->max_total_bytes ||
                    unpacked_size > limits->max_total_bytes - total_uncompressed) {
                    return QW_STATUS_ERR_RESOURCE_LIMIT;
                }
                if (!has_data && unpacked_size != 0u)
                    return QW_STATUS_ERR_FORMAT;
                if (is_stored && data_size != unpacked_size)
                    return QW_STATUS_ERR_FORMAT;
                if (unpacked_size > UINT64_MAX - total_uncompressed)
                    return QW_STATUS_ERR_FORMAT;
                total_uncompressed += unpacked_size;
                payload = bytes + header_end;
                payload_size = (size_t)data_size;
                if (is_stored && has_crc32 &&
                    qw_crc32_ieee(payload, payload_size) != data_crc32) {
                    return QW_STATUS_ERR_FORMAT;
                }
                {
                    QwRarEntry entry;
                    memset(&entry, 0, sizeof(entry));
                    entry.name = name;
                    entry.name_size = (size_t)name_size;
                    entry.packed_data = payload;
                    entry.packed_size = payload_size;
                    entry.uncompressed_size = unpacked_size;
                    entry.data_crc32 = data_crc32;
                    entry.archive_flags = archive_flags;
                    entry.format_flags = file_flags;
                    entry.compression_info = compression_info;
                    entry.compression_method = compression_method;
                    entry.format_version = 5u;
                    entry.compression_version =
                        (uint8_t)(compression_info & 0x3fu);
                    entry.is_directory = 0;
                    entry.is_stored = is_stored;
                    entry.is_solid =
                        (compression_info & UINT64_C(0x40)) != 0u;
                    entry.has_data_crc32 = has_crc32;
                    rc = visit_entry(context, &entry);
                    if (rc != QW_STATUS_OK) return rc;
                }
            } else if (is_file && is_directory &&
                       (unpacked_size != 0u || data_size != 0u)) {
                return QW_STATUS_ERR_FORMAT;
            } else if (is_file && is_directory) {
                QwRarEntry entry;
                memset(&entry, 0, sizeof(entry));
                entry.name = name;
                entry.name_size = (size_t)name_size;
                entry.archive_flags = archive_flags;
                entry.format_flags = file_flags;
                entry.compression_info = compression_info;
                entry.compression_method =
                    (uint32_t)((compression_info & UINT64_C(0x0380)) >> 7u);
                entry.format_version = 5u;
                entry.compression_version =
                    (uint8_t)(compression_info & 0x3fu);
                entry.is_directory = 1;
                entry.is_solid =
                    (compression_info & UINT64_C(0x40)) != 0u;
                rc = visit_entry(context, &entry);
                if (rc != QW_STATUS_OK) return rc;
            }
        } else if (header_type == RAR5_HEADER_END) {
            uint64_t end_flags;
            if (!main_seen || has_data ||
                !rar5_read_vint(bytes, header_end, &body_position, &end_flags)) {
                return QW_STATUS_ERR_FORMAT;
            }
            if (end_flags & 1u) return QW_STATUS_ERR_UNSUPPORTED;
            if (end_flags & ~UINT64_C(1)) return QW_STATUS_ERR_UNSUPPORTED;
            if (body_position != header_end) return QW_STATUS_ERR_FORMAT;
            end_seen = 1;
            position = next_position;
            break;
        } else {
            if ((header_flags & RAR5_HEADER_FLAG_UNKNOWN_TYPE_SKIP) == 0u)
                return QW_STATUS_ERR_UNSUPPORTED;
            if (!rar5_header_extra_bounds(body_position, header_end,
                                          extra_size, &extra_begin)) {
                return QW_STATUS_ERR_FORMAT;
            }
            if (has_extra) {
                rc = rar5_validate_extra_area(bytes, extra_begin, header_end, 0);
                if (rc != QW_STATUS_OK) return rc;
            } else if (body_position != header_end) {
                return QW_STATUS_ERR_FORMAT;
            }
        }
        position = next_position;
    }
    if (!main_seen || !end_seen) return QW_STATUS_ERR_FORMAT;
    return QW_STATUS_OK;
}
