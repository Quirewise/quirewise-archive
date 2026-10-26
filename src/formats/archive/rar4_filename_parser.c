#include "rar4_filename_parser.h"

#include <stdlib.h>
#include <string.h>

static int rar4_append_utf16_unit(uint16_t **units,
                                  size_t *unit_count,
                                  size_t *unit_capacity,
                                  size_t unit_limit,
                                  uint16_t value)
{
    size_t new_capacity;
    uint16_t *new_units;

    if (*unit_count >= unit_limit) return QW_STATUS_ERR_RESOURCE_LIMIT;
    if (*unit_count == *unit_capacity) {
        if (*unit_capacity == 0u) {
            new_capacity = unit_limit < 32u ? unit_limit : 32u;
        } else if (*unit_capacity > unit_limit / 2u) {
            new_capacity = unit_limit;
        } else {
            new_capacity = *unit_capacity * 2u;
        }
        if (new_capacity > SIZE_MAX / sizeof(**units))
            return QW_STATUS_ERR_RESOURCE_LIMIT;
        new_units = (uint16_t *)realloc(*units,
                                        new_capacity * sizeof(**units));
        if (!new_units) return QW_STATUS_ERR_OUT_OF_MEMORY;
        *units = new_units;
        *unit_capacity = new_capacity;
    }

    (*units)[(*unit_count)++] = value;
    return QW_STATUS_OK;
}

static size_t rar4_encode_utf8(uint32_t codepoint, uint8_t *output)
{
    if (codepoint < 0x80u) {
        output[0] = (uint8_t)codepoint;
        return 1u;
    }
    if (codepoint < 0x800u) {
        output[0] = (uint8_t)(0xc0u | (codepoint >> 6u));
        output[1] = (uint8_t)(0x80u | (codepoint & 0x3fu));
        return 2u;
    }
    if (codepoint < 0x10000u) {
        output[0] = (uint8_t)(0xe0u | (codepoint >> 12u));
        output[1] = (uint8_t)(0x80u | ((codepoint >> 6u) & 0x3fu));
        output[2] = (uint8_t)(0x80u | (codepoint & 0x3fu));
        return 3u;
    }

    output[0] = (uint8_t)(0xf0u | (codepoint >> 18u));
    output[1] = (uint8_t)(0x80u | ((codepoint >> 12u) & 0x3fu));
    output[2] = (uint8_t)(0x80u | ((codepoint >> 6u) & 0x3fu));
    output[3] = (uint8_t)(0x80u | (codepoint & 0x3fu));
    return 4u;
}

static int rar4_utf16_units_to_utf8(const uint16_t *units,
                                    size_t unit_count,
                                    uint8_t **utf8_out,
                                    size_t *utf8_size_out)
{
    uint8_t *utf8;
    size_t capacity;
    size_t unit_index = 0u;
    size_t utf8_size = 0u;

    if (unit_count > (SIZE_MAX - 1u) / 3u)
        return QW_STATUS_ERR_RESOURCE_LIMIT;
    capacity = unit_count * 3u + 1u;
    utf8 = (uint8_t *)malloc(capacity);
    if (!utf8) return QW_STATUS_ERR_OUT_OF_MEMORY;

    while (unit_index < unit_count) {
        uint32_t codepoint = units[unit_index++];

        if (codepoint >= 0xd800u && codepoint <= 0xdbffu) {
            uint32_t low_surrogate;
            if (unit_index >= unit_count) {
                free(utf8);
                return QW_STATUS_ERR_FORMAT;
            }
            low_surrogate = units[unit_index++];
            if (low_surrogate < 0xdc00u || low_surrogate > 0xdfffu) {
                free(utf8);
                return QW_STATUS_ERR_FORMAT;
            }
            codepoint = 0x10000u + ((codepoint - 0xd800u) << 10u) +
                        (low_surrogate - 0xdc00u);
        } else if (codepoint >= 0xdc00u && codepoint <= 0xdfffu) {
            free(utf8);
            return QW_STATUS_ERR_FORMAT;
        }
        if (codepoint == 0u) {
            free(utf8);
            return QW_STATUS_ERR_FORMAT;
        }

        utf8_size += rar4_encode_utf8(codepoint, utf8 + utf8_size);
    }

    utf8[utf8_size] = 0u;
    *utf8_out = utf8;
    *utf8_size_out = utf8_size;
    return QW_STATUS_OK;
}

int qw_rar4_decode_compressed_unicode_name(const uint8_t *fallback_name,
                                          size_t fallback_name_size,
                                          const uint8_t *encoded_name,
                                          size_t encoded_name_size,
                                          uint8_t **utf8_name_out,
                                          size_t *utf8_name_size_out)
{
    uint16_t *units = NULL;
    size_t unit_count = 0u;
    size_t unit_capacity = 0u;
    size_t unit_limit;
    size_t encoded_position = 0u;
    uint8_t high_byte;
    uint8_t flags = 0u;
    unsigned int flag_bits = 0u;
    int rc = QW_STATUS_OK;

    if (!fallback_name || !encoded_name || !utf8_name_out ||
        !utf8_name_size_out) {
        return QW_STATUS_ERR_INVALID_ARGUMENT;
    }
    *utf8_name_out = NULL;
    *utf8_name_size_out = 0u;
    if (!fallback_name_size || encoded_name_size < 2u)
        return QW_STATUS_ERR_FORMAT;
    if (encoded_name_size > SIZE_MAX / 129u)
        return QW_STATUS_ERR_RESOURCE_LIMIT;
    unit_limit = encoded_name_size * 129u;

    high_byte = encoded_name[encoded_position++];
    while (encoded_position < encoded_name_size) {
        uint16_t value;
        unsigned int mode;

        if (flag_bits == 0u) {
            flags = encoded_name[encoded_position++];
            flag_bits = 8u;
            if (encoded_position >= encoded_name_size) {
                rc = QW_STATUS_ERR_FORMAT;
                goto cleanup;
            }
        }
        mode = (unsigned int)(flags >> 6u);
        switch (mode) {
        case 0u:
            value = encoded_name[encoded_position++];
            break;
        case 1u:
            value = (uint16_t)(encoded_name[encoded_position++] |
                               ((uint16_t)high_byte << 8u));
            break;
        case 2u:
            if (encoded_name_size - encoded_position < 2u) {
                rc = QW_STATUS_ERR_FORMAT;
                goto cleanup;
            }
            value = (uint16_t)(encoded_name[encoded_position] |
                               ((uint16_t)encoded_name[encoded_position + 1u]
                                << 8u));
            encoded_position += 2u;
            break;
        case 3u:
        {
            uint8_t length_byte;
            size_t run_length;
            uint8_t correction = 0u;
            int corrected;
            size_t run_index;

            if (encoded_position >= encoded_name_size) {
                rc = QW_STATUS_ERR_FORMAT;
                goto cleanup;
            }
            length_byte = encoded_name[encoded_position++];
            corrected = (length_byte & 0x80u) != 0u;
            run_length = (size_t)(length_byte & 0x7fu) + 2u;
            if (corrected) {
                if (encoded_position >= encoded_name_size) {
                    rc = QW_STATUS_ERR_FORMAT;
                    goto cleanup;
                }
                correction = encoded_name[encoded_position++];
            }
            if (run_length > fallback_name_size -
                             (unit_count < fallback_name_size
                                  ? unit_count : fallback_name_size)) {
                rc = QW_STATUS_ERR_FORMAT;
                goto cleanup;
            }
            for (run_index = 0u; run_index < run_length; ++run_index) {
                uint8_t low_byte = fallback_name[unit_count];
                value = low_byte;
                if (corrected) {
                    low_byte = (uint8_t)(low_byte + correction);
                    value = (uint16_t)(low_byte |
                                       ((uint16_t)high_byte << 8u));
                }
                rc = rar4_append_utf16_unit(&units, &unit_count,
                                            &unit_capacity, unit_limit, value);
                if (rc != QW_STATUS_OK) goto cleanup;
            }
            break;
        }
        default:
            rc = QW_STATUS_ERR_FORMAT;
            goto cleanup;
        }

        if (mode != 3u) {
            rc = rar4_append_utf16_unit(&units, &unit_count, &unit_capacity,
                                        unit_limit, value);
            if (rc != QW_STATUS_OK) goto cleanup;
        }
        flags = (uint8_t)(flags << 2u);
        flag_bits -= 2u;
    }

    if (unit_count == 0u) {
        rc = QW_STATUS_ERR_FORMAT;
        goto cleanup;
    }
    rc = rar4_utf16_units_to_utf8(units, unit_count, utf8_name_out,
                                  utf8_name_size_out);

cleanup:
    free(units);
    return rc;
}

int qw_rar4_decode_entry_name(const uint8_t *stored_name,
                              size_t stored_name_size,
                              int has_unicode_flag,
                              const uint8_t **name_out,
                              size_t *name_size_out,
                              uint8_t **owned_name_out)
{
    const uint8_t *separator;
    int rc;

    if (!stored_name || !name_out || !name_size_out || !owned_name_out)
        return QW_STATUS_ERR_INVALID_ARGUMENT;
    *name_out = NULL;
    *name_size_out = 0u;
    *owned_name_out = NULL;
    if (stored_name_size == 0u) return QW_STATUS_ERR_FORMAT;

    separator = has_unicode_flag
        ? (const uint8_t *)memchr(stored_name, 0, stored_name_size)
        : NULL;
    if (separator) {
        size_t fallback_size = (size_t)(separator - stored_name);
        rc = qw_rar4_decode_compressed_unicode_name(
            stored_name, fallback_size, separator + 1u,
            stored_name_size - fallback_size - 1u,
            owned_name_out, name_size_out);
        if (rc != QW_STATUS_OK) return rc;
        *name_out = *owned_name_out;
        return QW_STATUS_OK;
    }
    if (!has_unicode_flag && memchr(stored_name, 0, stored_name_size))
        return QW_STATUS_ERR_FORMAT;

    *name_out = stored_name;
    *name_size_out = stored_name_size;
    return QW_STATUS_OK;
}
