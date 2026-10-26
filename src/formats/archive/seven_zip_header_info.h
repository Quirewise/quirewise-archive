#ifndef QUIREWISE_SEVEN_ZIP_HEADER_INFO_H
#define QUIREWISE_SEVEN_ZIP_HEADER_INFO_H

#include "seven_zip_files_info.h"
#include "seven_zip_native.h"
#include "seven_zip_streams.h"

typedef struct QwSevenZipHeaderInfo {
    QwSevenZipStreamInfo streams;
    QwSevenZipFilesInfo files;
    int has_streams;
} QwSevenZipHeaderInfo;

int qw_seven_zip_header_info_parse(const QwSevenZipHeader *header,
                                   QwSevenZipHeaderInfo *out_info);
void qw_seven_zip_header_info_dispose(QwSevenZipHeaderInfo *info);
QwSevenZipHeaderResult qw_seven_zip_header_has_image(
    const void *data, size_t size, int *out_has_image);

#endif
