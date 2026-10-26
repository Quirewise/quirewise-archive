#include "seven_zip_extract.h"

#include "seven_zip_header_info.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define SEVEN_ZIP_EXTRACT_MEMORY_LIMIT (256u * 1024u * 1024u)
#define SEVEN_ZIP_EXTRACT_CHUNK_SIZE (64u * 1024u)

static int seven_zip_streams_match_files(
    const QwSevenZipFilesInfo *files_info,
    const QwSevenZipStreamInfo *streams,
    int has_streams)
{
    size_t empty_index = 0u;
    size_t data_file_count = 0u;
    uint64_t size_sum = 0u;
    if (!files_info) return 0;
    for (size_t i = 0u; i < files_info->file_count; ++i) {
        int has_stream;
        int is_directory;
        int is_anti;
        qw_seven_zip_files_info_entry_state(
            files_info, i, &empty_index, &has_stream, &is_directory,
            &is_anti);
        (void)is_directory;
        (void)is_anti;
        if (has_stream) ++data_file_count;
    }
    if (!data_file_count) return !has_streams;
    if (!has_streams || data_file_count != streams->substream_count) return 0;
    for (size_t i = 0u; i < streams->substream_count; ++i) {
        if (streams->substreams[i].unpack_size > UINT64_MAX - size_sum)
            return 0;
        size_sum += streams->substreams[i].unpack_size;
    }
    return size_sum == streams->unpack_size;
}

static int seven_zip_emit_entry(const QwSevenZipSink *sink,
                                uint32_t archive_index,
                                const char *name,
                                uint64_t declared_size,
                                int is_directory,
                                const uint8_t *contents)
{
    void *entry = NULL;
    int begin_result;
    if (!sink || !sink->begin || !sink->write || !sink->finish) return 0;
    begin_result = sink->begin(sink->context, archive_index, name,
                               declared_size, is_directory, &entry);
    if (begin_result != 0) {
        sink->finish(sink->context, entry, begin_result);
        return 0;
    }
    if (entry && declared_size) {
        uint64_t position = 0u;
        while (position < declared_size) {
            size_t chunk = (size_t)(declared_size - position);
            if (chunk > SEVEN_ZIP_EXTRACT_CHUNK_SIZE)
                chunk = SEVEN_ZIP_EXTRACT_CHUNK_SIZE;
            if (sink->write(sink->context, entry,
                            contents + (size_t)position, chunk) != 0) {
                sink->finish(sink->context, entry, 1);
                return 0;
            }
            position += (uint64_t)chunk;
        }
    }
    sink->finish(sink->context, entry, 0);
    return 1;
}

static int seven_zip_emit_entries(const QwSevenZipFilesInfo *files_info,
                                  const QwSevenZipStreamInfo *streams,
                                  const uint8_t *decoded,
                                  const QwSevenZipSink *sink)
{
    size_t empty_index = 0u;
    size_t substream_index = 0u;
    uint64_t data_position = 0u;
    for (size_t i = 0u; i < files_info->file_count; ++i) {
        int has_stream;
        int is_directory;
        int is_anti;
        uint64_t entry_size = 0u;
        const uint8_t *entry_data = NULL;
        qw_seven_zip_files_info_entry_state(
            files_info, i, &empty_index, &has_stream, &is_directory,
            &is_anti);
        if (is_anti) continue;
        if (has_stream) {
            const QwSevenZipSubstream *substream;
            uLong crc;
            if (substream_index >= streams->substream_count ||
                !files_info->names || !files_info->names[i]) return 0;
            substream = &streams->substreams[substream_index++];
            if (substream->unpack_size > (uint64_t)SIZE_MAX ||
                data_position > streams->unpack_size ||
                substream->unpack_size > streams->unpack_size - data_position)
                return 0;
            entry_size = substream->unpack_size;
            entry_data = decoded + (size_t)data_position;
            if (substream->has_crc) {
                crc = crc32(0L, Z_NULL, 0);
                crc = crc32(crc, entry_data, (uInt)entry_size);
                if ((uint32_t)crc != substream->crc) return 0;
            }
            data_position += substream->unpack_size;
        } else if (!is_directory && (!files_info->names || !files_info->names[i])) {
            return 0;
        }
        if (!seven_zip_emit_entry(sink, (uint32_t)i,
                                  files_info->names && files_info->names[i]
                                      ? files_info->names[i] : "",
                                  entry_size, is_directory, entry_data))
            return 0;
    }
    return substream_index == streams->substream_count &&
           data_position == streams->unpack_size;
}

int qw_seven_zip_extract_memory(const void *data, size_t size,
                                const char *password,
                                const QwSevenZipSink *sink)
{
    QwSevenZipHeader header = {0};
    QwSevenZipHeaderInfo header_info = {0};
    QwSevenZipHeaderResult header_result;
    uint8_t *decoded = NULL;
    int result = QW_SEVEN_ZIP_EXTRACT_INVALID;
    if (!data || !size || !sink || !sink->begin || !sink->write ||
        !sink->finish) return QW_SEVEN_ZIP_EXTRACT_INVALID;
    if (password && *password) return QW_SEVEN_ZIP_EXTRACT_UNSUPPORTED;
    header_result = qw_seven_zip_header_open(data, size, &header);
    if (header_result == QW_SEVEN_ZIP_HEADER_INVALID) return result;
    if (header_result != QW_SEVEN_ZIP_HEADER_NATIVE)
        return QW_SEVEN_ZIP_EXTRACT_UNSUPPORTED;
    if (!qw_seven_zip_header_info_parse(&header, &header_info)) {
        result = QW_SEVEN_ZIP_EXTRACT_UNSUPPORTED;
        goto done;
    }
    if (!seven_zip_streams_match_files(&header_info.files,
                                       &header_info.streams,
                                       header_info.has_streams)) {
        result = QW_SEVEN_ZIP_EXTRACT_UNSUPPORTED;
        goto done;
    }
    if (header_info.has_streams) {
        if (header_info.streams.unpack_size >
                (uint64_t)SEVEN_ZIP_EXTRACT_MEMORY_LIMIT ||
            header_info.streams.unpack_size > (uint64_t)SIZE_MAX) {
            result = QW_SEVEN_ZIP_EXTRACT_RESOURCE_LIMIT;
            goto done;
        }
        decoded = (uint8_t *)malloc((size_t)header_info.streams.unpack_size);
        if (!decoded) {
            result = QW_SEVEN_ZIP_EXTRACT_OUT_OF_MEMORY;
            goto done;
        }
        if (!qw_seven_zip_stream_info_decode(
                (const uint8_t *)data, size, header.next_header_offset,
                &header_info.streams, decoded,
                (size_t)header_info.streams.unpack_size)) {
            result = QW_SEVEN_ZIP_EXTRACT_DECODE_ERROR;
            goto done;
        }
    }
    if (!seven_zip_emit_entries(&header_info.files, &header_info.streams,
                                decoded, sink)) {
        result = QW_SEVEN_ZIP_EXTRACT_SINK_ERROR;
        goto done;
    }
    result = QW_SEVEN_ZIP_EXTRACT_OK;
done:
    free(decoded);
    qw_seven_zip_header_info_dispose(&header_info);
    qw_seven_zip_header_close(&header);
    return result;
}
