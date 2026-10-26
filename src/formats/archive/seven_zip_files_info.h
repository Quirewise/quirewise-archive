#ifndef QUIREWISE_SEVEN_ZIP_FILES_INFO_H
#define QUIREWISE_SEVEN_ZIP_FILES_INFO_H

#include <stddef.h>
#include <stdint.h>

typedef struct QwSevenZipFilesInfo {
    size_t file_count;
    char **names;
    const uint8_t *empty_stream_bits;
    size_t empty_stream_size;
    const uint8_t *empty_file_bits;
    size_t empty_file_size;
    const uint8_t *anti_bits;
    size_t anti_size;
    size_t empty_stream_count;
    int has_empty_stream;
    int has_empty_file;
    int has_anti;
} QwSevenZipFilesInfo;

int qw_seven_zip_files_info_parse(const uint8_t *header, size_t size,
                                  size_t start,
                                  QwSevenZipFilesInfo *out_info);
void qw_seven_zip_files_info_dispose(QwSevenZipFilesInfo *info);
int qw_seven_zip_files_info_has_image(const QwSevenZipFilesInfo *info);
void qw_seven_zip_files_info_entry_state(const QwSevenZipFilesInfo *info,
                                        size_t file_index,
                                        size_t *empty_index,
                                        int *out_has_stream,
                                        int *out_is_directory,
                                        int *out_is_anti);

#endif
