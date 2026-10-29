#include "seven_zip_codec.h"
#include "zip_native.h"

#include <quirewise/archive.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s at line %d\n", #condition, __LINE__); \
        return 1; \
    } \
} while (0)

static int hex_value(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static size_t decode_hex(const char *hex, uint8_t *output, size_t capacity)
{
    size_t length = strlen(hex);
    size_t i;
    if ((length & 1u) || length / 2u > capacity) return 0u;
    for (i = 0u; i < length / 2u; ++i) {
        int high = hex_value(hex[i * 2u]);
        int low = hex_value(hex[i * 2u + 1u]);
        if (high < 0 || low < 0) return 0u;
        output[i] = (uint8_t)((high << 4) | low);
    }
    return length / 2u;
}

static int test_seven_zip_deflate(void)
{
    static const uint8_t expected[] =
        "The quick brown fox jumps over the lazy dog. "
        "The quick brown fox jumps over the lazy dog.";
    static const char stream_hex[] =
        "0bc94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae724"
        "56552aa4e4a7eb298490a01800";
    uint8_t stream[64];
    uint8_t decoded[sizeof(expected) - 1u];
    size_t stream_size = decode_hex(stream_hex, stream, sizeof(stream));
    QwSevenZipCoder coder = {0x040108u, NULL, 0u};
    if (!stream_size ||
        !qw_seven_zip_decode_chain(&coder, 1u, stream, stream_size,
                                   decoded, sizeof(decoded)) ||
        memcmp(decoded, expected, sizeof(decoded)) != 0) {
        fputs("7z Deflate known-answer decode failed\n", stderr);
        return 0;
    }
    if (qw_seven_zip_decode_chain(&coder, 1u, stream, stream_size,
                                  decoded, sizeof(decoded) - 1u)) {
        fputs("7z Deflate accepted an incorrect output size\n", stderr);
        return 0;
    }
    return 1;
}

static int test_seven_zip_lzma(void)
{
    static const uint8_t expected[] =
        "Quirewise 7z raw LZMA fixture\n"
        "Quirewise 7z raw LZMA fixture\n"
        "Quirewise 7z raw LZMA fixture\n"
        "Quirewise 7z raw LZMA fixture\n"
        "Quirewise 7z raw LZMA fixture\n"
        "Quirewise 7z raw LZMA fixture\n"
        "Quirewise 7z raw LZMA fixture\n"
        "Quirewise 7z raw LZMA fixture\n"
        "Quirewise 7z raw LZMA fixture\n"
        "Quirewise 7z raw LZMA fixture\n";
    static const char lzma1_hex[] =
        "00289d4927558dc1605540399fcd93704cde5761cb836d0e855ab19589d6f409"
        "32219e3ed7f3fffff5b0c000";
    static const char lzma2_hex[] =
        "e0012b00265d00289d4927558dc1605540399fcd93704cde5761cb836d0e855ab"
        "19589d6f40932219e28ea000000";
    static const uint8_t lzma1_properties[] = {0x5du, 0u, 0u, 0x10u, 0u};
    static const uint8_t lzma2_properties[] = {0x10u};
    uint8_t lzma1_stream[64];
    uint8_t lzma2_stream[64];
    uint8_t decoded[sizeof(expected) - 1u];
    size_t lzma1_size = decode_hex(lzma1_hex, lzma1_stream,
                                   sizeof(lzma1_stream));
    size_t lzma2_size = decode_hex(lzma2_hex, lzma2_stream,
                                   sizeof(lzma2_stream));
    QwSevenZipCoder coder;

    if (!lzma1_size || !lzma2_size) return 0;
    coder = (QwSevenZipCoder){QW_COMPRESSION_7Z_LZMA1_METHOD,
                              lzma1_properties,
                              sizeof(lzma1_properties)};
    if (!qw_seven_zip_decode_chain(&coder, 1u, lzma1_stream, lzma1_size,
                                   decoded, sizeof(decoded)) ||
        memcmp(decoded, expected, sizeof(decoded)) != 0) {
        fputs("7z LZMA1 known-answer decode failed\n", stderr);
        return 0;
    }

    coder = (QwSevenZipCoder){QW_COMPRESSION_7Z_LZMA2_METHOD,
                              lzma2_properties,
                              sizeof(lzma2_properties)};
    if (!qw_seven_zip_decode_chain(&coder, 1u, lzma2_stream, lzma2_size,
                                   decoded, sizeof(decoded)) ||
        memcmp(decoded, expected, sizeof(decoded)) != 0) {
        fputs("7z LZMA2 known-answer decode failed\n", stderr);
        return 0;
    }
    return 1;
}

static int test_zip_writer_round_trip(void)
{
    static const char expected[] = "ZIP writer uses internal stored DEFLATE.";
    QwZipWriter writer = {0};
    QwZipArchiveReader *reader = NULL;
    QwArchiveEntry entry = {0};
    QwArchiveBuffer extracted = {0};
    const char *error = NULL;
    void *archive_data = NULL;
    size_t archive_size = 0u;
    QwArchiveStatus status;
    int ok = 0;

    if (!qw_zip_writer_init_heap(&writer, 0u, 0u) ||
        !qw_zip_writer_add_mem(&writer, "payload.txt", expected,
                               sizeof(expected) - 1u,
                               QW_ZIP_DEFAULT_COMPRESSION) ||
        !qw_zip_writer_finalize_heap_archive(&writer,
                                             &archive_data, &archive_size)) {
        fputs("ZIP writer failed to encode a compressed entry\n", stderr);
        goto done;
    }
    qw_zip_writer_end(&writer);
    status = qw_zip_archive_open(archive_data, archive_size, &reader, &error);
    if (status != QW_ARCHIVE_OK || !reader ||
        qw_zip_archive_entry_count(reader) != 1u ||
        qw_zip_archive_get_entry(reader, 0u, &entry) != QW_ARCHIVE_OK ||
        entry.compression_method != 8u ||
        qw_zip_archive_extract(reader, 0u, NULL, &extracted) != QW_ARCHIVE_OK ||
        extracted.size != sizeof(expected) - 1u ||
        memcmp(extracted.data, expected, sizeof(expected) - 1u) != 0) {
        fprintf(stderr, "ZIP writer round trip failed: %s\n",
                error ? error : "entry extraction mismatch");
        goto done;
    }
    ok = 1;

done:
    qw_archive_buffer_free(&extracted);
    qw_zip_archive_close(reader);
    qw_zip_writer_end(&writer);
    free(archive_data);
    return ok;
}

int main(void)
{
    CHECK(test_seven_zip_deflate());
    CHECK(test_seven_zip_lzma());
    CHECK(test_zip_writer_round_trip());
    puts("PASS: Archive ZIP, 7z Deflate, LZMA1, and LZMA2 use Quirewise Compression");
    return 0;
}
