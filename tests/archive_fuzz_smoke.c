#include <quirewise/archive.h>
#include <quirewise/rar.h>
#include <quirewise/seven_zip.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FUZZ_SEED UINT32_C(0x51f09955)
#define FUZZ_RUNS 200u

static uint32_t rng_state = FUZZ_SEED;

static const uint8_t zip_seed[116] = {
    0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0xae, 0x9a,
    0x66, 0x5d, 0xa4, 0x09, 0x07, 0x7a, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00,
    0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x31, 0x2e, 0x70, 0x6e, 0x67, 0x89,
    0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x50, 0x4b, 0x01, 0x02, 0x14,
    0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0xae, 0x9a, 0x66, 0x5d, 0xa4,
    0x09, 0x07, 0x7a, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x31, 0x2e, 0x70, 0x6e, 0x67, 0x50, 0x4b,
    0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x33, 0x00,
    0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t rar_seed[] = {0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00};
static const uint8_t seven_seed[] = {0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04};

static uint32_t next_random(void)
{
    uint32_t value = rng_state;
    value ^= value << 13u;
    value ^= value >> 17u;
    value ^= value << 5u;
    rng_state = value;
    return value;
}

static size_t mutate(const uint8_t *seed, size_t seed_size, uint8_t *buffer,
                     size_t capacity)
{
    size_t length = seed_size > capacity ? capacity : seed_size;
    unsigned int flips = 1u + next_random() % 4u;
    size_t index;
    memcpy(buffer, seed, length);
    if (next_random() % 8u == 0u && length > 1u)
        length = 1u + next_random() % length;
    for (index = 0u; index < flips && length; ++index) {
        size_t position = next_random() % length;
        buffer[position] = (uint8_t)(buffer[position] ^
                                     (uint8_t)(1u << (next_random() % 8u)));
    }
    return length;
}

static QwArchiveTarVisitAction tar_visitor(void *context, const char *name,
                                           const uint8_t *data, size_t size)
{
    (void)context;
    (void)name;
    (void)data;
    (void)size;
    return QW_ARCHIVE_TAR_STOP;
}

static QwRarVisitAction rar_visitor(void *context, const QwRarEntryView *entry)
{
    (void)context;
    (void)entry;
    return QW_RAR_VISIT_STOP;
}

static int seven_begin(void *context, uint32_t index, const char *name,
                       uint64_t size, int is_directory, void **out_entry)
{
    (void)context;
    (void)index;
    (void)name;
    (void)size;
    (void)is_directory;
    (void)out_entry;
    return 0;
}

static int seven_write(void *context, void *entry, const void *data,
                       size_t size)
{
    (void)context;
    (void)entry;
    (void)data;
    (void)size;
    return 0;
}

static void seven_finish(void *context, void *entry, int result)
{
    (void)context;
    (void)entry;
    (void)result;
}

static void put_octal(char *field, size_t width, unsigned int value)
{
    size_t index;
    for (index = 0u; index < width - 1u; ++index) field[index] = '0';
    field[width - 1u] = '\0';
    for (index = width - 1u; index > 0u && value; --index) {
        field[index - 1u] = (char)('0' + (value & 7u));
        value >>= 3;
    }
}

static size_t build_tar(uint8_t *archive, size_t capacity)
{
    unsigned int checksum = 0u;
    size_t index;
    if (capacity < 1536u) return 0u;
    memset(archive, 0, 1536u);
    memcpy(archive, "node.txt", 8u);
    put_octal((char *)archive + 100, 8u, 0644u);
    put_octal((char *)archive + 124, 12u, 4u);
    memset(archive + 148, ' ', 8u);
    archive[156] = '0';
    memcpy(archive + 257, "ustar", 6u);
    memcpy(archive + 263, "00", 2u);
    for (index = 0u; index < 512u; ++index) checksum += archive[index];
    put_octal((char *)archive + 148, 7u, checksum);
    archive[155] = ' ';
    memcpy(archive + 512, "node", 4u);
    return 1024u;
}

int main(void)
{
    uint8_t buffer[1536];
    uint8_t tar[1536];
    size_t tar_size = build_tar(tar, sizeof(tar));
    size_t run;
    size_t ok = 0u;
    size_t rejected = 0u;
    for (run = 0u; run < FUZZ_RUNS; ++run) {
        QwZipArchiveReader *reader = NULL;
        const char *error = NULL;
        size_t size = mutate(zip_seed, sizeof(zip_seed), buffer, sizeof(buffer));
        if (qw_zip_archive_open(buffer, size, &reader, &error) == QW_ARCHIVE_OK &&
            reader) {
            ++ok;
            qw_zip_archive_close(reader);
        } else {
            ++rejected;
        }
    }
    for (run = 0u; run < FUZZ_RUNS; ++run) {
        size_t size = mutate(rar_seed, sizeof(rar_seed), buffer, sizeof(buffer));
        if (qw_rar_archive_visit(buffer, size, NULL, rar_visitor, NULL) ==
            QW_RAR_OK)
            ++ok;
        else
            ++rejected;
    }
    for (run = 0u; run < FUZZ_RUNS; ++run) {
        size_t size = mutate(tar, tar_size, buffer, sizeof(buffer));
        if (qw_tar_archive_visit_ustar(buffer, size, tar_visitor, NULL) ==
            QW_ARCHIVE_OK)
            ++ok;
        else
            ++rejected;
    }
    for (run = 0u; run < FUZZ_RUNS; ++run) {
        QwSevenZipSink sink = {NULL, seven_begin, seven_write, seven_finish};
        size_t size = mutate(seven_seed, sizeof(seven_seed), buffer,
                             sizeof(buffer));
        size_t next = 0u;
        int status = qw_seven_zip_probe(buffer, size, &next);
        if (status == QW_SEVEN_ZIP_OK) ++ok; else ++rejected;
        status = qw_seven_zip_extract(buffer, size, NULL, &sink);
        if (status == QW_SEVEN_ZIP_OK) ++ok; else ++rejected;
    }
    printf("Archive fuzz smoke: %zu ok, %zu rejected, seed=0x%08x runs=%u\n", ok,
           rejected, FUZZ_SEED, FUZZ_RUNS);
    return 0;
}
