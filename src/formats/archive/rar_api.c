#include "quirewise/rar.h"

#include "quirewise/status.h"
#include "rar4_parser.h"
#include "rar5_parser.h"

#include <string.h>

typedef struct QwRarVisitContext {
    QwRarEntryVisitor visitor;
    void *context;
    int stopped;
    int failed;
} QwRarVisitContext;

static int rar_visit_bridge(void *opaque, const QwRarEntry *entry)
{
    QwRarVisitContext *context = (QwRarVisitContext *)opaque;
    QwRarEntryView view;
    QwRarVisitAction action;
    if (!context || !entry || !context->visitor) return QW_STATUS_ERR_INVALID_ARGUMENT;
    memset(&view, 0, sizeof(view));
    view.name = entry->name;
    view.name_size = entry->name_size;
    view.packed_data = entry->packed_data;
    view.packed_size = entry->packed_size;
    view.uncompressed_size = entry->uncompressed_size;
    view.data_crc32 = entry->data_crc32;
    view.archive_flags = entry->archive_flags;
    view.format_flags = entry->format_flags;
    view.compression_info = entry->compression_info;
    view.compression_method = entry->compression_method;
    view.format_version = entry->format_version;
    view.compression_version = entry->compression_version;
    view.is_directory = entry->is_directory;
    view.is_stored = entry->is_stored;
    view.is_solid = entry->is_solid;
    view.has_data_crc32 = entry->has_data_crc32;
    action = context->visitor(context->context, &view);
    if (action == QW_RAR_VISIT_STOP) {
        context->stopped = 1;
        return QW_STATUS_ERR_IO;
    }
    if (action != QW_RAR_VISIT_CONTINUE) {
        context->failed = 1;
        return QW_STATUS_ERR_IO;
    }
    return QW_STATUS_OK;
}

static QwRarStatus rar_status_map(int rc)
{
    switch (rc) {
    case QW_STATUS_OK: return QW_RAR_OK;
    case QW_STATUS_ERR_INVALID_ARGUMENT: return QW_RAR_ERR_INVALID_ARGUMENT;
    case QW_STATUS_ERR_OUT_OF_MEMORY: return QW_RAR_ERR_OUT_OF_MEMORY;
    case QW_STATUS_ERR_FORMAT: return QW_RAR_ERR_FORMAT;
    case QW_STATUS_ERR_UNSUPPORTED: return QW_RAR_ERR_UNSUPPORTED;
    case QW_STATUS_ERR_RESOURCE_LIMIT: return QW_RAR_ERR_RESOURCE_LIMIT;
    default: return QW_RAR_ERR_FORMAT;
    }
}

QwRarStatus qw_rar_archive_visit(const void *data,
                                 size_t size,
                                 const QwRarParseLimits *limits,
                                 QwRarEntryVisitor visitor,
                                 void *context)
{
    static const QwRarParseLimits defaults = {
        100000u, UINT64_C(1099511627776), UINT64_C(4398046511104)
    };
    QwRarVisitContext visit_context;
    const QwRarParseLimits *effective_limits = limits ? limits : &defaults;
    QwRarLimits internal_limits;
    int rc;

    if (!data || !size || !visitor) return QW_RAR_ERR_INVALID_ARGUMENT;
    internal_limits.max_entries = effective_limits->max_entries;
    internal_limits.max_entry_bytes = effective_limits->max_entry_bytes;
    internal_limits.max_total_bytes = effective_limits->max_total_bytes;
    memset(&visit_context, 0, sizeof(visit_context));
    visit_context.visitor = visitor;
    visit_context.context = context;
    rc = qw_rar4_parse_entries((const uint8_t *)data, size,
                               &internal_limits,
                               rar_visit_bridge, &visit_context);
    if (rc == QW_STATUS_ERR_UNSUPPORTED) {
        rc = qw_rar5_parse_entries((const uint8_t *)data, size,
                                   &internal_limits,
                                   rar_visit_bridge, &visit_context);
    }
    if (visit_context.stopped) return QW_RAR_STOPPED;
    if (visit_context.failed) return QW_RAR_ERR_CALLBACK;
    return rar_status_map(rc);
}
