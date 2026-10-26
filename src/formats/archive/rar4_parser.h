#ifndef QUIREWISE_RAR4_PARSER_H
#define QUIREWISE_RAR4_PARSER_H

#include "rar_parser.h"

/* Parses RAR 1.5–4.x headers and visits file entries with borrowed names and
 * packed-data slices. It validates container metadata but does not decompress
 * entries; callers route compressed payloads to a decoder. Entry names and
 * payloads remain valid only during the callback. Unsupported archive flags
 * and variants return QW_STATUS_ERR_UNSUPPORTED.
 */
int qw_rar4_parse_entries(const uint8_t *bytes,
                          size_t size,
                          const QwRarLimits *limits,
                          QwRarEntryFn visit_entry,
                          void *context);

#endif
