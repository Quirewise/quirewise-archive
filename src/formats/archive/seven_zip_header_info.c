#include "seven_zip_header_info.h"

#include <stdlib.h>

enum {
    SEVEN_ZIP_ID_HEADER = 0x01u,
    SEVEN_ZIP_ID_ARCHIVE_PROPERTIES = 0x02u,
    SEVEN_ZIP_ID_ADDITIONAL_STREAMS_INFO = 0x03u,
    SEVEN_ZIP_ID_MAIN_STREAMS_INFO = 0x04u,
    SEVEN_ZIP_ID_FILES_INFO = 0x05u,
    SEVEN_ZIP_ID_END = 0x00u
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

static int seven_zip_skip_archive_properties(const uint8_t *header,
                                             size_t size,
                                             size_t *position)
{
    while (*position < size) {
        uint8_t property = header[(*position)++];
        uint64_t property_size;
        if (property == SEVEN_ZIP_ID_END) return 1;
        if (!seven_zip_read_number(header, size, position, &property_size) ||
            property_size > (uint64_t)(size - *position)) return 0;
        *position += (size_t)property_size;
    }
    return 0;
}

static int seven_zip_parse_main_streams(const uint8_t *header, size_t size,
                                        size_t *position,
                                        QwSevenZipStreamInfo *streams,
                                        int *out_has_streams)
{
    if (*position >= size || header[(*position)++] !=
        SEVEN_ZIP_ID_MAIN_STREAMS_INFO) return 0;
    if (*position < size && header[*position] == SEVEN_ZIP_ID_END) {
        ++*position;
        *out_has_streams = 0;
        return 1;
    }
    if (!qw_seven_zip_stream_info_parse(header, size, position, streams) ||
        *position >= size || header[(*position)++] != SEVEN_ZIP_ID_END)
        return 0;
    *out_has_streams = 1;
    return 1;
}

int qw_seven_zip_header_info_parse(const QwSevenZipHeader *header,
                                   QwSevenZipHeaderInfo *out_info)
{
    size_t position = 0u;
    int has_archive_properties = 0;
    int has_main_streams = 0;
    int has_files = 0;
    QwSevenZipHeaderInfo parsed = {0};
    if (!out_info) return 0;
    *out_info = (QwSevenZipHeaderInfo){0};
    if (!header || !header->bytes || !header->size ||
        header->bytes[position++] != SEVEN_ZIP_ID_HEADER) return 0;
    while (position < header->size) {
        uint8_t property = header->bytes[position++];
        if (property == SEVEN_ZIP_ID_END) break;
        if (property == SEVEN_ZIP_ID_ARCHIVE_PROPERTIES) {
            if (has_archive_properties ||
                !seven_zip_skip_archive_properties(header->bytes,
                                                  header->size, &position))
                goto error;
            has_archive_properties = 1;
        } else if (property == SEVEN_ZIP_ID_ADDITIONAL_STREAMS_INFO) {
            goto error;
        } else if (property == SEVEN_ZIP_ID_MAIN_STREAMS_INFO) {
            --position;
            if (has_main_streams || !seven_zip_parse_main_streams(
                    header->bytes, header->size, &position,
                    &parsed.streams, &parsed.has_streams)) goto error;
            has_main_streams = 1;
        } else if (property == SEVEN_ZIP_ID_FILES_INFO) {
            --position;
            if (has_files || !qw_seven_zip_files_info_parse(
                    header->bytes, header->size, position, &parsed.files))
                goto error;
            has_files = 1;
            position = header->size;
            break;
        } else {
            goto error;
        }
    }
    if (position != header->size || !has_files) goto error;
    *out_info = parsed;
    return 1;
error:
    qw_seven_zip_header_info_dispose(&parsed);
    return 0;
}

void qw_seven_zip_header_info_dispose(QwSevenZipHeaderInfo *info)
{
    if (!info) return;
    qw_seven_zip_stream_info_dispose(&info->streams);
    qw_seven_zip_files_info_dispose(&info->files);
    *info = (QwSevenZipHeaderInfo){0};
}

#ifndef QUIREWISE_STANDALONE_SEVEN_ZIP
QwSevenZipHeaderResult qw_seven_zip_header_has_image(
    const void *data, size_t size, int *out_has_image)
{
    QwSevenZipHeader header = {0};
    QwSevenZipHeaderInfo info = {0};
    QwSevenZipHeaderResult result;
    if (out_has_image) *out_has_image = 0;
    if (!out_has_image) return QW_SEVEN_ZIP_HEADER_INVALID;
    result = qw_seven_zip_header_open(data, size, &header);
    if (result != QW_SEVEN_ZIP_HEADER_NATIVE) return result;
    if (!qw_seven_zip_header_info_parse(&header, &info)) {
        qw_seven_zip_header_close(&header);
        return QW_SEVEN_ZIP_HEADER_UNSUPPORTED;
    }
    *out_has_image = qw_seven_zip_files_info_has_image(&info.files);
    qw_seven_zip_header_info_dispose(&info);
    qw_seven_zip_header_close(&header);
    return QW_SEVEN_ZIP_HEADER_NATIVE;
}
#endif
