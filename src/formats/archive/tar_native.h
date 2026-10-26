#ifndef QUIREWISE_TAR_NATIVE_H
#define QUIREWISE_TAR_NATIVE_H

#include "../../core/architecture_metadata.h"

#include <stddef.h>
#include <stdint.h>

typedef int (*QwUstarEntryVisitor)(void *context,
                                   const char *name,
                                   const uint8_t *data,
                                   size_t size);

enum { QW_TAR_VISITOR_STOP = 1 };

int qw_tar_visit_ustar(const void *data, size_t size,
                       const QwFormatInputResourceProfile *profile,
                       QwUstarEntryVisitor visitor,
                       void *visitor_context);

#endif
