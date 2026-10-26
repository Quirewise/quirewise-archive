#include "quirewise/archive.h"

#include "tar_native.h"
#include "zip_native.h"
#include "quirewise/status.h"

#include <stdlib.h>

struct QwZipArchiveReader {
    QwZipArchive archive;
};

typedef struct QwTarVisitContext {
    QwArchiveTarVisitor visitor;
    void *user_context;
    int stopped;
    int aborted;
} QwTarVisitContext;

static int qw_archive_tar_visit_adapter(void *context, const char *name,
                                        const uint8_t *data, size_t size)
{
    QwTarVisitContext *visit = (QwTarVisitContext *)context;
    QwArchiveTarVisitAction action = visit->visitor(
        visit->user_context, name, data, size);
    if (action == QW_ARCHIVE_TAR_CONTINUE) return QW_STATUS_OK;
    if (action == QW_ARCHIVE_TAR_STOP) {
        visit->stopped = 1;
        return QW_TAR_VISITOR_STOP;
    }
    visit->aborted = 1;
    return QW_STATUS_ERR_UNSUPPORTED;
}

static QwArchiveStatus qw_archive_tar_status(int status)
{
    switch (status) {
    case QW_STATUS_OK: return QW_ARCHIVE_OK;
    case QW_STATUS_ERR_INVALID_ARGUMENT: return QW_ARCHIVE_ERR_INVALID_ARGUMENT;
    case QW_STATUS_ERR_OUT_OF_MEMORY: return QW_ARCHIVE_ERR_OUT_OF_MEMORY;
    case QW_STATUS_ERR_RESOURCE_LIMIT: return QW_ARCHIVE_ERR_RESOURCE_LIMIT;
    case QW_STATUS_ERR_UNSUPPORTED: return QW_ARCHIVE_ERR_UNSUPPORTED;
    case QW_STATUS_ERR_FORMAT: return QW_ARCHIVE_ERR_FORMAT;
    default: return QW_ARCHIVE_ERR_FORMAT;
    }
}

uint32_t qw_archive_abi_version(void)
{
    return QUIREWISE_ARCHIVE_ABI_VERSION;
}

QwArchiveStatus qw_zip_archive_open(const void *data, size_t size,
                                   QwZipArchiveReader **out_reader,
                                   const char **out_error)
{
    QwZipArchiveReader *reader;
    const char *error;

    if (out_reader) *out_reader = NULL;
    if (out_error) *out_error = NULL;
    if (!out_reader || !data || !size)
        return QW_ARCHIVE_ERR_INVALID_ARGUMENT;

    reader = (QwZipArchiveReader *)calloc(1u, sizeof(*reader));
    if (!reader) return QW_ARCHIVE_ERR_OUT_OF_MEMORY;
    if (!qw_zip_reader_init_mem(&reader->archive, data, size, 0u)) {
        error = qw_zip_archive_error(&reader->archive);
        if (out_error) *out_error = error;
        qw_zip_reader_end(&reader->archive);
        free(reader);
        return QW_ARCHIVE_ERR_OPEN;
    }

    *out_reader = reader;
    return QW_ARCHIVE_OK;
}

void qw_zip_archive_close(QwZipArchiveReader *reader)
{
    if (!reader) return;
    qw_zip_reader_end(&reader->archive);
    free(reader);
}

size_t qw_zip_archive_entry_count(const QwZipArchiveReader *reader)
{
    return reader ? qw_zip_reader_get_num_files(&reader->archive) : 0u;
}

QwArchiveStatus qw_zip_archive_get_entry(const QwZipArchiveReader *reader,
                                         size_t index,
                                         QwArchiveEntry *out_entry)
{
    const QwZipEntry *entry;
    if (out_entry) *out_entry = (QwArchiveEntry){0};
    if (!reader || !out_entry) return QW_ARCHIVE_ERR_INVALID_ARGUMENT;
    if (index >= reader->archive.count) return QW_ARCHIVE_ERR_INDEX;

    entry = &reader->archive.entries[index];
    out_entry->name_bytes = (const uint8_t *)entry->name;
    out_entry->name_size = entry->name_size;
    out_entry->compressed_size = entry->compressed_size;
    out_entry->uncompressed_size = entry->uncompressed_size;
    out_entry->crc32 = entry->crc32;
    out_entry->flags = entry->flags;
    out_entry->compression_method = entry->method;
    out_entry->is_directory = entry->is_directory;
    return QW_ARCHIVE_OK;
}

QwArchiveStatus qw_zip_archive_extract(QwZipArchiveReader *reader,
                                       size_t index,
                                       const char *password,
                                       QwArchiveBuffer *out_buffer)
{
    void *data;
    size_t size = 0u;
    if (out_buffer) {
        out_buffer->data = NULL;
        out_buffer->size = 0u;
    }
    if (!reader || !out_buffer) return QW_ARCHIVE_ERR_INVALID_ARGUMENT;
    if (index >= reader->archive.count) return QW_ARCHIVE_ERR_INDEX;
    if (reader->archive.entries[index].is_directory ||
        !qw_zip_reader_is_file_supported(&reader->archive, index)) {
        reader->archive.error = "unsupported ZIP entry";
        return QW_ARCHIVE_ERR_UNSUPPORTED;
    }

    data = qw_zip_reader_extract_to_heap_with_password(
        &reader->archive, index, &size, password);
    if (!data) return QW_ARCHIVE_ERR_EXTRACT;
    out_buffer->data = (uint8_t *)data;
    out_buffer->size = size;
    return QW_ARCHIVE_OK;
}

QwArchiveStatus qw_tar_archive_visit_ustar(const void *data, size_t size,
                                           QwArchiveTarVisitor visitor,
                                           void *visitor_context)
{
    QwTarVisitContext context = {0};
    int status;
    if (!visitor) return QW_ARCHIVE_ERR_INVALID_ARGUMENT;
    context.visitor = visitor;
    context.user_context = visitor_context;
    status = qw_tar_visit_ustar(data, size,
                                QW_FORMAT_INPUT_RESOURCE_PROFILE_DEFAULT,
                                qw_archive_tar_visit_adapter, &context);
    if (context.stopped) return QW_ARCHIVE_OK;
    if (context.aborted) return QW_ARCHIVE_ERR_CALLBACK;
    return qw_archive_tar_status(status);
}

void qw_archive_buffer_free(QwArchiveBuffer *buffer)
{
    if (!buffer) return;
    free(buffer->data);
    buffer->data = NULL;
    buffer->size = 0u;
}

const char *qw_zip_archive_last_error(const QwZipArchiveReader *reader)
{
    return reader ? qw_zip_archive_error(&reader->archive) : NULL;
}

const char *qw_archive_status_string(int status)
{
    switch (status) {
    case QW_ARCHIVE_OK: return "ok";
    case QW_ARCHIVE_ERR_INVALID_ARGUMENT: return "invalid argument";
    case QW_ARCHIVE_ERR_OUT_OF_MEMORY: return "out of memory";
    case QW_ARCHIVE_ERR_OPEN: return "could not open ZIP archive";
    case QW_ARCHIVE_ERR_UNSUPPORTED: return "unsupported ZIP entry";
    case QW_ARCHIVE_ERR_EXTRACT: return "could not extract ZIP entry";
    case QW_ARCHIVE_ERR_INDEX: return "entry index is out of range";
    case QW_ARCHIVE_ERR_CALLBACK: return "TAR visitor aborted";
    case QW_ARCHIVE_ERR_FORMAT: return "invalid archive structure";
    case QW_ARCHIVE_ERR_RESOURCE_LIMIT: return "archive resource limit exceeded";
    default: return "unknown archive status";
    }
}
