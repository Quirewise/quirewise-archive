#include "tar_native.h"

#include "quirewise/status.h"

#include <stdlib.h>
#include <string.h>

enum {
    QW_TAR_BLOCK_SIZE = 512u,
    QW_TAR_MAX_EXTENDED_BYTES = 1024u * 1024u
};

typedef struct QwTarOverrides {
    char *path;
    uint64_t size;
    int has_size;
} QwTarOverrides;

static int tar_is_ustar_signature(const uint8_t *bytes, size_t size)
{
    return bytes && size >= 262u &&
           memcmp(bytes + 257u, "ustar", 5u) == 0;
}

static int tar_is_zero_block(const uint8_t *block)
{
    for (size_t i = 0u; i < QW_TAR_BLOCK_SIZE; ++i)
        if (block[i] != 0u) return 0;
    return 1;
}

static int tar_read_number(const uint8_t *field, size_t field_size,
                           uint64_t *out_value)
{
    uint64_t value = 0u;
    size_t i;
    int has_digit = 0;
    int ended = 0;
    if (!field || !field_size || !out_value) return 0;
    if (field[0] & 0x80u) {
        if (field[0] & 0x40u) return 0;
        value = (uint64_t)(field[0] & 0x3fu);
        for (i = 1u; i < field_size; ++i) {
            if (value > (UINT64_MAX - field[i]) / 256u) return 0;
            value = value * 256u + field[i];
        }
        *out_value = value;
        return 1;
    }
    for (i = 0u; i < field_size; ++i) {
        uint8_t byte = field[i];
        if (byte >= (uint8_t)'0' && byte <= (uint8_t)'7') {
            uint64_t digit = (uint64_t)(byte - (uint8_t)'0');
            if (ended || value > (UINT64_MAX - digit) / 8u) return 0;
            value = value * 8u + digit;
            has_digit = 1;
        } else if (byte == 0u || byte == (uint8_t)' ') {
            if (has_digit) ended = 1;
        } else {
            return 0;
        }
    }
    *out_value = value;
    return 1;
}

static int tar_header_valid(const uint8_t *header)
{
    uint64_t expected;
    uint64_t checksum = 0u;
    if (!header ||
        memcmp(header + 257u, "ustar", 5u) != 0 ||
        !tar_read_number(header + 148u, 8u, &expected)) {
        return 0;
    }
    for (size_t i = 0u; i < QW_TAR_BLOCK_SIZE; ++i)
        checksum += (i >= 148u && i < 156u) ? (uint8_t)' ' : header[i];
    return checksum == expected;
}

static size_t tar_field_length(const uint8_t *field, size_t capacity)
{
    size_t length = 0u;
    while (length < capacity && field[length] != 0u) ++length;
    return length;
}

static char *tar_header_name(const uint8_t *header)
{
    size_t name_size = tar_field_length(header, 100u);
    size_t prefix_size = tar_field_length(header + 345u, 155u);
    size_t total_size;
    char *name;
    if (!name_size || prefix_size > SIZE_MAX - name_size - 2u) return NULL;
    total_size = prefix_size ? prefix_size + 1u + name_size : name_size;
    name = (char *)malloc(total_size + 1u);
    if (!name) return NULL;
    if (prefix_size) {
        memcpy(name, header + 345u, prefix_size);
        name[prefix_size] = '/';
        memcpy(name + prefix_size + 1u, header, name_size);
    } else {
        memcpy(name, header, name_size);
    }
    name[total_size] = '\0';
    return name;
}

static int tar_set_path(QwTarOverrides *overrides,
                        const uint8_t *value, size_t value_size)
{
    char *path;
    if (!overrides || (!value && value_size)) return QW_STATUS_ERR_INVALID_ARGUMENT;
    if (value_size == SIZE_MAX ||
        (value_size && memchr(value, 0, value_size) != NULL))
        return QW_STATUS_ERR_FORMAT;
    path = (char *)malloc(value_size + 1u);
    if (!path) return QW_STATUS_ERR_OUT_OF_MEMORY;
    if (value_size) memcpy(path, value, value_size);
    path[value_size] = '\0';
    free(overrides->path);
    overrides->path = path;
    return QW_STATUS_OK;
}

static int tar_set_long_path(QwTarOverrides *overrides,
                             const uint8_t *value, size_t value_size)
{
    while (value_size &&
           (value[value_size - 1u] == 0u ||
            value[value_size - 1u] == (uint8_t)'\n' ||
            value[value_size - 1u] == (uint8_t)'\r')) {
        --value_size;
    }
    return tar_set_path(overrides, value, value_size);
}

static int tar_parse_decimal(const uint8_t *value, size_t value_size,
                             uint64_t *out_value)
{
    uint64_t parsed = 0u;
    if (!value || !value_size || !out_value) return QW_STATUS_ERR_FORMAT;
    for (size_t i = 0u; i < value_size; ++i) {
        uint8_t byte = value[i];
        uint64_t digit;
        if (byte < (uint8_t)'0' || byte > (uint8_t)'9')
            return QW_STATUS_ERR_FORMAT;
        digit = (uint64_t)(byte - (uint8_t)'0');
        if (parsed > (UINT64_MAX - digit) / 10u) return QW_STATUS_ERR_FORMAT;
        parsed = parsed * 10u + digit;
    }
    *out_value = parsed;
    return QW_STATUS_OK;
}

static int tar_parse_pax(const uint8_t *data, size_t size,
                         QwTarOverrides *overrides)
{
    size_t position = 0u;
    if ((!data && size) || !overrides) return QW_STATUS_ERR_INVALID_ARGUMENT;
    while (position < size) {
        size_t record_start = position;
        size_t record_size = 0u;
        size_t value_start;
        size_t record_end;
        size_t content_end;
        size_t equals = SIZE_MAX;
        int has_length_digit = 0;
        int rc;
        while (position < size &&
               data[position] >= (uint8_t)'0' &&
               data[position] <= (uint8_t)'9') {
            uint8_t digit = (uint8_t)(data[position] - (uint8_t)'0');
            if (record_size > (SIZE_MAX - digit) / 10u)
                return QW_STATUS_ERR_FORMAT;
            record_size = record_size * 10u + digit;
            ++position;
            has_length_digit = 1;
        }
        if (!has_length_digit || position >= size ||
            data[position] != (uint8_t)' ') return QW_STATUS_ERR_FORMAT;
        ++position;
        if (record_size < position - record_start + 2u ||
            record_size > size - record_start) return QW_STATUS_ERR_FORMAT;
        record_end = record_start + record_size;
        content_end = record_end;
        if (data[content_end - 1u] != (uint8_t)'\n')
            return QW_STATUS_ERR_FORMAT;
        --content_end;
        value_start = position;
        for (size_t i = value_start; i < content_end; ++i) {
            if (data[i] == (uint8_t)'=') {
                equals = i;
                break;
            }
        }
        if (equals == SIZE_MAX || equals == value_start)
            return QW_STATUS_ERR_FORMAT;
        if (equals - value_start >= 11u &&
            memcmp(data + value_start, "GNU.sparse.", 11u) == 0)
            return QW_STATUS_ERR_UNSUPPORTED;
        if (equals - value_start == 4u &&
            memcmp(data + value_start, "path", 4u) == 0) {
            rc = tar_set_path(overrides, data + equals + 1u,
                              content_end - equals - 1u);
            if (rc != QW_STATUS_OK) return rc;
        } else if (equals - value_start == 4u &&
                   memcmp(data + value_start, "size", 4u) == 0) {
            rc = tar_parse_decimal(data + equals + 1u,
                                   content_end - equals - 1u,
                                   &overrides->size);
            if (rc != QW_STATUS_OK) return rc;
            overrides->has_size = 1;
        }
        position = record_end;
    }
    return QW_STATUS_OK;
}

int qw_tar_visit_ustar(const void *data, size_t size,
                       const QwFormatInputResourceProfile *profile,
                       QwUstarEntryVisitor visitor,
                       void *visitor_context)
{
    const uint8_t *bytes = (const uint8_t *)data;
    QwTarOverrides global = {0};
    QwTarOverrides local = {0};
    size_t offset = 0u;
    size_t header_count = 0u;
    uint64_t archive_total = 0u;
    int rc = QW_STATUS_ERR_FORMAT;

    if (!data || !size || !profile || !visitor)
        return QW_STATUS_ERR_INVALID_ARGUMENT;
    if (!profile->max_archive_input_bytes || !profile->max_archive_entries ||
        !profile->max_archive_entry_bytes ||
        !profile->max_archive_total_bytes) return QW_STATUS_ERR_RESOURCE_LIMIT;
    if (size > profile->max_archive_input_bytes) return QW_STATUS_ERR_RESOURCE_LIMIT;
    if (!tar_is_ustar_signature(bytes, size)) return QW_STATUS_ERR_FORMAT;

    while (offset < size) {
        const uint8_t *header;
        const uint8_t *payload;
        uint64_t raw_size = 0u;
        uint64_t entry_size;
        uint64_t padded_size;
        size_t remaining = size - offset;
        uint8_t type;
        int is_extension;
        if (remaining < QW_TAR_BLOCK_SIZE) {
            for (size_t i = offset; i < size; ++i) {
                if (bytes[i] != 0u) goto cleanup;
            }
            offset = size;
            break;
        }
        header = bytes + offset;
        if (tar_is_zero_block(header)) {
            for (size_t i = offset; i < size; ++i) {
                if (bytes[i] != 0u) goto cleanup;
            }
            offset = size;
            break;
        }
        if (header_count >= profile->max_archive_entries) {
            rc = QW_STATUS_ERR_RESOURCE_LIMIT;
            goto cleanup;
        }
        ++header_count;
        if (!tar_header_valid(header) ||
            !tar_read_number(header + 124u, 12u, &raw_size)) {
            rc = QW_STATUS_ERR_FORMAT;
            goto cleanup;
        }
        type = header[156u];
        if (type == (uint8_t)'S') {
            rc = QW_STATUS_ERR_UNSUPPORTED;
            goto cleanup;
        }
        is_extension = type == (uint8_t)'x' || type == (uint8_t)'g' ||
                       type == (uint8_t)'L' || type == (uint8_t)'K';
        entry_size = raw_size;
        if (!is_extension) {
            if (local.has_size) entry_size = local.size;
            else if (global.has_size) entry_size = global.size;
        }
        if (entry_size > profile->max_archive_entry_bytes ||
            archive_total > profile->max_archive_total_bytes ||
            entry_size > profile->max_archive_total_bytes - archive_total) {
            rc = QW_STATUS_ERR_RESOURCE_LIMIT;
            goto cleanup;
        }
        if (entry_size > UINT64_MAX -
                ((QW_TAR_BLOCK_SIZE -
                  (entry_size % QW_TAR_BLOCK_SIZE)) % QW_TAR_BLOCK_SIZE)) {
            rc = QW_STATUS_ERR_FORMAT;
            goto cleanup;
        }
        padded_size = entry_size +
            ((QW_TAR_BLOCK_SIZE -
              (entry_size % QW_TAR_BLOCK_SIZE)) % QW_TAR_BLOCK_SIZE);
        if (padded_size > remaining - QW_TAR_BLOCK_SIZE) {
            rc = QW_STATUS_ERR_FORMAT;
            goto cleanup;
        }
        payload = header + QW_TAR_BLOCK_SIZE;

        if (is_extension) {
            if (raw_size > QW_TAR_MAX_EXTENDED_BYTES ||
                raw_size > SIZE_MAX) {
                rc = QW_STATUS_ERR_UNSUPPORTED;
                goto cleanup;
            }
            archive_total += raw_size;
            if (type == (uint8_t)'x' || type == (uint8_t)'g') {
                QwTarOverrides *target =
                    type == (uint8_t)'x' ? &local : &global;
                rc = tar_parse_pax(payload, (size_t)raw_size, target);
                if (rc != QW_STATUS_OK) goto cleanup;
            } else if (type == (uint8_t)'L') {
                rc = tar_set_long_path(&local, payload, (size_t)raw_size);
                if (rc != QW_STATUS_OK) goto cleanup;
            }
            offset += QW_TAR_BLOCK_SIZE + (size_t)padded_size;
            continue;
        }

        archive_total += entry_size;
        if (type == 0u || type == (uint8_t)'0' || type == (uint8_t)'7') {
            char *header_name = NULL;
            const char *entry_name;
            int visitor_rc;
            if (local.path) entry_name = local.path;
            else if (global.path) entry_name = global.path;
            else {
                header_name = tar_header_name(header);
                if (!header_name) {
                    rc = QW_STATUS_ERR_FORMAT;
                    goto cleanup;
                }
                entry_name = header_name;
            }
            if (entry_size > SIZE_MAX) {
                free(header_name);
                rc = QW_STATUS_ERR_UNSUPPORTED;
                goto cleanup;
            }
            visitor_rc = visitor(visitor_context, entry_name, payload,
                                 (size_t)entry_size);
            free(header_name);
            if (visitor_rc != QW_STATUS_OK) {
                rc = visitor_rc;
                goto cleanup;
            }
        }
        free(local.path);
        memset(&local, 0, sizeof(local));
        offset += QW_TAR_BLOCK_SIZE + (size_t)padded_size;
    }
    rc = QW_STATUS_OK;

cleanup:
    free(global.path);
    free(local.path);
    return rc;
}
