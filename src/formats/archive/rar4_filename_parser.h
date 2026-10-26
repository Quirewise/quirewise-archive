#ifndef QUIREWISE_RAR4_FILENAME_PARSER_H
#define QUIREWISE_RAR4_FILENAME_PARSER_H

#include "quirewise/status.h"

#include <stddef.h>
#include <stdint.h>

/* Return the stored name as a view, or an allocated UTF-8 name if compressed. */
int qw_rar4_decode_entry_name(const uint8_t *stored_name,
                              size_t stored_name_size,
                              int has_unicode_flag,
                              const uint8_t **name_out,
                              size_t *name_size_out,
                              uint8_t **owned_name_out);

/* Decode the RAR4 flag-based Unicode suffix into an allocated UTF-8 name. */
int qw_rar4_decode_compressed_unicode_name(const uint8_t *fallback_name,
                                          size_t fallback_name_size,
                                          const uint8_t *encoded_name,
                                          size_t encoded_name_size,
                                          uint8_t **utf8_name_out,
                                          size_t *utf8_name_size_out);

#endif
