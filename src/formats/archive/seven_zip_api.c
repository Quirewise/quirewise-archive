#include "quirewise/seven_zip.h"

#include "seven_zip_extract.h"
#include "seven_zip_native.h"

#include <string.h>

QwSevenZipStatus qw_seven_zip_probe(const void *data,
                                   size_t size,
                                   size_t *out_next_header_offset)
{
    QwSevenZipHeader header = {0};
    QwSevenZipHeaderResult result;
    if (!data || !size) return QW_SEVEN_ZIP_INVALID_ARGUMENT;
    result = qw_seven_zip_header_open(data, size, &header);
    if (result == QW_SEVEN_ZIP_HEADER_NATIVE) {
        if (out_next_header_offset)
            *out_next_header_offset = header.next_header_offset;
        qw_seven_zip_header_close(&header);
        return QW_SEVEN_ZIP_OK;
    }
    qw_seven_zip_header_close(&header);
    if (result == QW_SEVEN_ZIP_HEADER_UNSUPPORTED)
        return QW_SEVEN_ZIP_UNSUPPORTED;
    return QW_SEVEN_ZIP_FORMAT_ERROR;
}

QwSevenZipStatus qw_seven_zip_extract(const void *data,
                                     size_t size,
                                     const char *password,
                                     const QwSevenZipSink *sink)
{
    QwSevenZipSink internal_sink;
    int rc;
    if (!data || !size || !sink || !sink->begin || !sink->write ||
        !sink->finish) return QW_SEVEN_ZIP_INVALID_ARGUMENT;
    memset(&internal_sink, 0, sizeof(internal_sink));
    internal_sink.context = sink->context;
    internal_sink.begin = sink->begin;
    internal_sink.write = sink->write;
    internal_sink.finish = sink->finish;
    rc = qw_seven_zip_extract_memory(data, size, password, &internal_sink);
    switch (rc) {
    case QW_SEVEN_ZIP_EXTRACT_OK: return QW_SEVEN_ZIP_OK;
    case QW_SEVEN_ZIP_EXTRACT_INVALID: return QW_SEVEN_ZIP_INVALID_ARGUMENT;
    case QW_SEVEN_ZIP_EXTRACT_UNSUPPORTED: return QW_SEVEN_ZIP_UNSUPPORTED;
    case QW_SEVEN_ZIP_EXTRACT_DECODE_ERROR: return QW_SEVEN_ZIP_DECODE_ERROR;
    case QW_SEVEN_ZIP_EXTRACT_RESOURCE_LIMIT:
        return QW_SEVEN_ZIP_RESOURCE_LIMIT;
    case QW_SEVEN_ZIP_EXTRACT_SINK_ERROR: return QW_SEVEN_ZIP_SINK_ERROR;
    case QW_SEVEN_ZIP_EXTRACT_OUT_OF_MEMORY:
        return QW_SEVEN_ZIP_OUT_OF_MEMORY;
    default: return QW_SEVEN_ZIP_FORMAT_ERROR;
    }
}
