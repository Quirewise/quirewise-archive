#ifndef QUIREWISE_SEVEN_ZIP_STREAMS_H
#define QUIREWISE_SEVEN_ZIP_STREAMS_H

#include "seven_zip_codec.h"

#include <stddef.h>
#include <stdint.h>

typedef struct QwSevenZipSubstream {
    uint64_t unpack_size;
    uint32_t crc;
    int has_crc;
} QwSevenZipSubstream;

typedef struct QwSevenZipStreamInfo {
    uint64_t pack_position;
    uint64_t pack_size;
    uint64_t unpack_size;
    uint32_t pack_crc;
    uint32_t folder_crc;
    QwSevenZipCoder coders[QW_SEVEN_ZIP_MAX_CODERS];
    size_t coder_count;
    size_t output_stream_count;
    size_t unpacked_output_index;
    size_t substream_count;
    QwSevenZipSubstream *substreams;
    int has_pack_crc;
    int has_folder_crc;
} QwSevenZipStreamInfo;

int qw_seven_zip_stream_info_parse(const uint8_t *data, size_t size,
                                   size_t *position,
                                   QwSevenZipStreamInfo *out_info);
int qw_seven_zip_stream_info_decode(const uint8_t *archive,
                                    size_t archive_size,
                                    size_t next_header_offset,
                                    const QwSevenZipStreamInfo *info,
                                    uint8_t *decoded,
                                    size_t decoded_size);
void qw_seven_zip_stream_info_dispose(QwSevenZipStreamInfo *info);

#endif
