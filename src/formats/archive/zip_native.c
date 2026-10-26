#include "zip_native.h"
#include "zip_deflate.h"
#include "../../core/byte_utils.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

enum {
    ZIP_EOCD_SIGNATURE = 0x06054b50u,
    ZIP64_EOCD_SIGNATURE = 0x06064b50u,
    ZIP64_LOCATOR_SIGNATURE = 0x07064b50u,
    ZIP_CENTRAL_SIGNATURE = 0x02014b50u,
    ZIP_LOCAL_SIGNATURE = 0x04034b50u,
    ZIP_EOCD_SIZE = 22u,
    ZIP_EOCD_COMMENT_MAX = 65535u,
    ZIP64_LOCATOR_SIZE = 20u,
    ZIP64_EOCD_MIN_SIZE = 56u,
    ZIP_CENTRAL_SIZE = 46u,
    ZIP_LOCAL_SIZE = 30u,
    ZIP_FLAG_ENCRYPTED = 1u,
    ZIP_FLAG_STRONG_ENCRYPTION = 0x40u,
    ZIP_FLAG_UTF8 = 0x800u,
    ZIP_METHOD_STORE = 0u,
    ZIP_METHOD_DEFLATE = 8u,
    ZIP_EXTRA_ZIP64 = 1u
};

static int range_valid(size_t size, uint64_t offset, uint64_t length)
{
    return offset <= (uint64_t)size &&
           length <= (uint64_t)size - offset;
}

static int zip_fail(QwZipArchive *archive, const char *message)
{
    size_t i;
    if (archive) {
        archive->error = message;
        for (i = 0; i < archive->count; ++i) {
            free(archive->entries[i].name);
        }
        free(archive->entries);
        archive->entries = NULL;
        archive->count = 0;
        archive->data = NULL;
        archive->size = 0;
    }
    return 0;
}

static int zip_find_eocd(const uint8_t *data, size_t size, size_t *out_offset)
{
    size_t earliest;
    size_t offset;
    if (!data || !out_offset || size < ZIP_EOCD_SIZE) return 0;
    earliest = size > ZIP_EOCD_SIZE + ZIP_EOCD_COMMENT_MAX
        ? size - ZIP_EOCD_SIZE - ZIP_EOCD_COMMENT_MAX : 0u;
    offset = size - ZIP_EOCD_SIZE;
    for (;;) {
        if (qw_read_u32_le(data + offset) == ZIP_EOCD_SIGNATURE) {
            uint16_t comment_size = qw_read_u16_le(data + offset + 20u);
            if ((size_t)comment_size <= size - offset - ZIP_EOCD_SIZE) {
                *out_offset = offset;
                return 1;
            }
        }
        if (offset == earliest) break;
        --offset;
    }
    return 0;
}

static int zip64_value(const uint8_t *extra, size_t extra_size,
                       uint64_t *uncompressed_size,
                       uint64_t *compressed_size,
                       uint64_t *local_offset,
                       uint32_t *disk_start,
                       int need_uncompressed,
                       int need_compressed,
                       int need_offset,
                       int need_disk)
{
    size_t offset = 0;
    while (offset + 4u <= extra_size) {
        uint16_t id = qw_read_u16_le(extra + offset);
        uint16_t field_size = qw_read_u16_le(extra + offset + 2u);
        const uint8_t *field = extra + offset + 4u;
        size_t cursor = 0;
        if ((size_t)field_size > extra_size - offset - 4u) return 0;
        if (id == ZIP_EXTRA_ZIP64) {
            if (need_uncompressed) {
                if ((size_t)field_size - cursor < 8u) return 0;
                *uncompressed_size = qw_read_u64_le(field + cursor);
                cursor += 8u;
            }
            if (need_compressed) {
                if ((size_t)field_size - cursor < 8u) return 0;
                *compressed_size = qw_read_u64_le(field + cursor);
                cursor += 8u;
            }
            if (need_offset) {
                if ((size_t)field_size - cursor < 8u) return 0;
                *local_offset = qw_read_u64_le(field + cursor);
                cursor += 8u;
            }
            if (need_disk) {
                if ((size_t)field_size - cursor < 4u) return 0;
                *disk_start = qw_read_u32_le(field + cursor);
            }
            return 1;
        }
        offset += 4u + (size_t)field_size;
    }
    return !(need_uncompressed || need_compressed || need_offset || need_disk);
}

static int zip_parse_directory(QwZipArchive *archive, uint64_t directory_offset,
                               uint64_t directory_size, uint64_t entry_count,
                               size_t eocd_offset)
{
    uint64_t cursor = directory_offset;
    uint64_t end;
    uint64_t base = 0;
    uint64_t anchor = eocd_offset;
    uint64_t inferred_start;
    uint64_t expanded_size_total = 0u;
    int direct_directory_valid;
    size_t i;

    if (entry_count > archive->max_archive_entries) {
        return zip_fail(archive, "ZIP entry count exceeds its resource limit");
    }
    if (entry_count > SIZE_MAX / sizeof(*archive->entries) ||
        entry_count > directory_size / ZIP_CENTRAL_SIZE) {
        return zip_fail(archive, "ZIP entry count is too large");
    }

    direct_directory_valid = range_valid(archive->size, directory_offset,
                                         directory_size);
    if (direct_directory_valid && directory_size) {
        direct_directory_valid =
            qw_read_u32_le(archive->data + (size_t)directory_offset) ==
            ZIP_CENTRAL_SIGNATURE;
    }
    if (!direct_directory_valid && anchor >= directory_size) {
        inferred_start = anchor - directory_size;
        if (inferred_start >= directory_offset) {
            base = inferred_start - directory_offset;
        }
    }
    if (base) {
        if (directory_offset > UINT64_MAX - base) {
            return zip_fail(archive, "ZIP central directory offset overflow");
        }
        directory_offset += base;
        archive->base_offset = base;
    }
    if (!range_valid(archive->size, directory_offset, directory_size) ||
        directory_size > archive->size) {
        return zip_fail(archive, "ZIP central directory is outside the input");
    }
    end = directory_offset + directory_size;
    cursor = directory_offset;

    if (entry_count > 0) {
        archive->entries = (QwZipEntry *)calloc((size_t)entry_count,
                                                sizeof(*archive->entries));
        if (!archive->entries) {
            return zip_fail(archive, "out of memory for ZIP entries");
        }
    }
    archive->count = (size_t)entry_count;

    for (i = 0; i < archive->count; ++i) {
        const uint8_t *header;
        uint16_t name_size;
        uint16_t extra_size;
        uint16_t comment_size;
        uint16_t disk16;
        uint64_t uncomp_size;
        uint64_t comp_size;
        uint64_t local_offset;
        uint32_t disk_start;
        const uint8_t *name;
        const uint8_t *extra;
        size_t record_size;
        QwZipEntry *entry = &archive->entries[i];

        if (cursor > end || end - cursor < ZIP_CENTRAL_SIZE ||
            !range_valid(archive->size, cursor, ZIP_CENTRAL_SIZE)) {
            return zip_fail(archive, "truncated ZIP central directory");
        }
        header = archive->data + (size_t)cursor;
        if (qw_read_u32_le(header) != ZIP_CENTRAL_SIGNATURE) {
            return zip_fail(archive, "invalid ZIP central directory record");
        }
        name_size = qw_read_u16_le(header + 28u);
        extra_size = qw_read_u16_le(header + 30u);
        comment_size = qw_read_u16_le(header + 32u);
        record_size = ZIP_CENTRAL_SIZE + (size_t)name_size +
                      (size_t)extra_size + (size_t)comment_size;
        if (record_size > end - cursor ||
            !range_valid(archive->size, cursor, record_size)) {
            return zip_fail(archive, "truncated ZIP entry metadata");
        }

        uncomp_size = qw_read_u32_le(header + 24u);
        comp_size = qw_read_u32_le(header + 20u);
        local_offset = qw_read_u32_le(header + 42u);
        disk16 = qw_read_u16_le(header + 34u);
        disk_start = disk16;
        name = header + ZIP_CENTRAL_SIZE;
        extra = name + name_size;
        if (!zip64_value(extra, extra_size, &uncomp_size, &comp_size,
                         &local_offset, &disk_start,
                         uncomp_size == UINT32_MAX,
                         comp_size == UINT32_MAX,
                         local_offset == UINT32_MAX,
                         disk16 == UINT16_MAX)) {
            return zip_fail(archive, "invalid ZIP64 entry metadata");
        }
        if (uncomp_size > archive->max_single_expanded_bytes ||
            expanded_size_total > archive->max_total_expanded_bytes ||
            uncomp_size > archive->max_total_expanded_bytes -
                         expanded_size_total) {
            return zip_fail(archive,
                            "ZIP expanded data exceeds its resource limit");
        }
        expanded_size_total += uncomp_size;
        if (disk_start != 0u || memchr(name, 0, name_size) != NULL) {
            return zip_fail(archive, "unsupported multi-disk ZIP entry or name");
        }
        if (local_offset > UINT64_MAX - base) {
            return zip_fail(archive, "ZIP local header offset overflow");
        }
        entry->name = (char *)malloc((size_t)name_size + 1u);
        if (!entry->name) {
            return zip_fail(archive, "out of memory for ZIP entry name");
        }
        memcpy(entry->name, name, name_size);
        entry->name[name_size] = '\0';
        entry->name_size = name_size;
        entry->flags = qw_read_u16_le(header + 8u);
        entry->method = qw_read_u16_le(header + 10u);
        entry->dos_time = qw_read_u16_le(header + 12u);
        entry->dos_date = qw_read_u16_le(header + 14u);
        entry->crc32 = qw_read_u32_le(header + 16u);
        entry->compressed_size = comp_size;
        entry->uncompressed_size = uncomp_size;
        entry->local_header_offset = local_offset + base;
        entry->external_attributes = qw_read_u32_le(header + 38u);
        entry->is_directory =
            (name_size && (name[name_size - 1u] == '/' ||
                           name[name_size - 1u] == '\\')) ||
            (entry->external_attributes & 0x10u) != 0;
        cursor += record_size;
    }
    return 1;
}

int qw_zip_reader_init_mem_with_profile(
    QwZipArchive *archive, const void *data, size_t size, unsigned flags,
    const QwFormatInputResourceProfile *resource_profile)
{
    const uint8_t *bytes = (const uint8_t *)data;
    size_t eocd_offset;
    uint64_t directory_offset;
    uint64_t directory_size;
    uint64_t entry_count;
    uint16_t disk_number;
    uint16_t directory_disk;
    uint16_t entries_on_disk;
    uint16_t entries_total;
    (void)flags;

    if (!archive) return 0;
    memset(archive, 0, sizeof(*archive));
    if (!resource_profile) {
        archive->error = "ZIP resource profile is missing";
        return 0;
    }
    archive->max_archive_input_bytes =
        resource_profile->max_archive_input_bytes;
    archive->max_archive_entries = resource_profile->max_archive_entries;
    archive->max_single_expanded_bytes =
        resource_profile->max_archive_entry_bytes;
    archive->max_total_expanded_bytes =
        resource_profile->max_archive_total_bytes;
    if (!archive->max_archive_input_bytes ||
        !archive->max_archive_entries ||
        !archive->max_single_expanded_bytes ||
        archive->max_single_expanded_bytes > archive->max_total_expanded_bytes) {
        archive->error = "ZIP resource profile is incomplete";
        return 0;
    }
    if (size > archive->max_archive_input_bytes) {
        archive->error = "ZIP archive exceeds its input byte resource limit";
        return 0;
    }
    if (!bytes || !zip_find_eocd(bytes, size, &eocd_offset)) {
        archive->error = "ZIP end record was not found";
        return 0;
    }
    archive->data = bytes;
    archive->size = size;

    disk_number = qw_read_u16_le(bytes + eocd_offset + 4u);
    directory_disk = qw_read_u16_le(bytes + eocd_offset + 6u);
    entries_on_disk = qw_read_u16_le(bytes + eocd_offset + 8u);
    entries_total = qw_read_u16_le(bytes + eocd_offset + 10u);
    directory_size = qw_read_u32_le(bytes + eocd_offset + 12u);
    directory_offset = qw_read_u32_le(bytes + eocd_offset + 16u);
    entry_count = entries_total;
    if (disk_number != 0u || directory_disk != 0u ||
        (entries_on_disk != entries_total &&
         entries_on_disk != UINT16_MAX && entries_total != UINT16_MAX)) {
        return zip_fail(archive, "multi-disk ZIP archives are unsupported");
    }

    if (eocd_offset >= ZIP64_LOCATOR_SIZE &&
        qw_read_u32_le(bytes + eocd_offset - ZIP64_LOCATOR_SIZE) ==
            ZIP64_LOCATOR_SIGNATURE) {
        const uint8_t *locator = bytes + eocd_offset - ZIP64_LOCATOR_SIZE;
        uint32_t zip64_disk = qw_read_u32_le(locator + 4u);
        uint64_t zip64_offset = qw_read_u64_le(locator + 8u);
        uint32_t disk_count = qw_read_u32_le(locator + 16u);
        const uint8_t *zip64;
        uint64_t zip64_record_size;
        uint64_t locator_offset = eocd_offset - ZIP64_LOCATOR_SIZE;
        if (zip64_disk != 0u || disk_count != 1u) {
            return zip_fail(archive, "invalid ZIP64 end record locator");
        }
        if (!range_valid(size, zip64_offset, ZIP64_EOCD_MIN_SIZE) ||
            qw_read_u32_le(bytes + (size_t)zip64_offset) != ZIP64_EOCD_SIGNATURE) {
            uint64_t earliest = locator_offset > 1024u * 1024u
                ? locator_offset - 1024u * 1024u : 0u;
            uint64_t candidate = locator_offset >= ZIP64_EOCD_MIN_SIZE
                ? locator_offset - ZIP64_EOCD_MIN_SIZE : 0u;
            int found = 0;
            for (;;) {
                if (candidate < earliest) break;
                if (qw_read_u32_le(bytes + (size_t)candidate) ==
                    ZIP64_EOCD_SIGNATURE) {
                    uint64_t candidate_size =
                        qw_read_u64_le(bytes + (size_t)candidate + 4u);
                    if (candidate_size <= UINT64_MAX - 12u &&
                        candidate <= locator_offset &&
                        locator_offset - candidate >= 12u &&
                        candidate_size == locator_offset - candidate - 12u) {
                        zip64_offset = candidate;
                        found = 1;
                        break;
                    }
                }
                if (candidate == earliest) break;
                --candidate;
            }
            if (!found) {
                return zip_fail(archive, "ZIP64 end record was not found");
            }
        }
        zip64 = bytes + (size_t)zip64_offset;
        if (qw_read_u32_le(zip64) != ZIP64_EOCD_SIGNATURE) {
            return zip_fail(archive, "ZIP64 end record was not found");
        }
        zip64_record_size = qw_read_u64_le(zip64 + 4u);
        if (zip64_record_size < ZIP64_EOCD_MIN_SIZE - 12u ||
            zip64_record_size > UINT64_MAX - 12u ||
            !range_valid(size, zip64_offset, zip64_record_size + 12u)) {
            return zip_fail(archive, "truncated ZIP64 end record");
        }
        if (qw_read_u32_le(zip64 + 16u) != 0u ||
            qw_read_u32_le(zip64 + 20u) != 0u ||
            qw_read_u64_le(zip64 + 24u) != qw_read_u64_le(zip64 + 32u)) {
            return zip_fail(archive, "multi-disk ZIP64 archives are unsupported");
        }
        entry_count = qw_read_u64_le(zip64 + 32u);
        directory_size = qw_read_u64_le(zip64 + 40u);
        directory_offset = qw_read_u64_le(zip64 + 48u);
        eocd_offset = (size_t)zip64_offset;
    } else if (entries_total == UINT16_MAX ||
               directory_size == UINT32_MAX ||
               directory_offset == UINT32_MAX) {
        return zip_fail(archive, "ZIP64 end record locator is missing");
    }

    return zip_parse_directory(archive, directory_offset, directory_size,
                               entry_count, eocd_offset);
}

void qw_zip_reader_end(QwZipArchive *archive)
{
    size_t i;
    if (!archive) return;
    for (i = 0; i < archive->count; ++i) free(archive->entries[i].name);
    free(archive->entries);
    memset(archive, 0, sizeof(*archive));
}

size_t qw_zip_reader_get_num_files(const QwZipArchive *archive)
{
    return archive ? archive->count : 0u;
}

size_t qw_zip_reader_get_filename(const QwZipArchive *archive, size_t index,
                                  char *buffer, size_t buffer_size)
{
    const QwZipEntry *entry;
    if (!archive || index >= archive->count) return SIZE_MAX;
    entry = &archive->entries[index];
    if (!buffer) return entry->name_size;
    if (entry->name_size >= buffer_size) return 0u;
    memcpy(buffer, entry->name, entry->name_size + 1u);
    return entry->name_size;
}

int qw_zip_reader_file_stat(const QwZipArchive *archive, size_t index,
                            QwZipEntryInfo *info)
{
    const QwZipEntry *entry;
    if (!archive || !info || index >= archive->count) return 0;
    entry = &archive->entries[index];
    info->compressed_size = entry->compressed_size;
    info->uncompressed_size = entry->uncompressed_size;
    info->crc32 = entry->crc32;
    info->flags = entry->flags;
    info->method = entry->method;
    return 1;
}

int qw_zip_reader_init_mem(QwZipArchive *archive, const void *data,
                           size_t size, unsigned flags)
{
    return qw_zip_reader_init_mem_with_profile(
        archive, data, size, flags,
        QW_FORMAT_INPUT_RESOURCE_PROFILE_DEFAULT);
}

int qw_zip_reader_is_file_supported(const QwZipArchive *archive, size_t index)
{
    const QwZipEntry *entry;
    if (!archive || index >= archive->count) return 0;
    entry = &archive->entries[index];
    if (entry->flags & ZIP_FLAG_STRONG_ENCRYPTION) return 0;
    return entry->method == ZIP_METHOD_STORE ||
           entry->method == ZIP_METHOD_DEFLATE;
}

int qw_zip_reader_is_file_a_directory(const QwZipArchive *archive,
                                      size_t index)
{
    return archive && index < archive->count
        ? archive->entries[index].is_directory : 0;
}

int qw_zip_reader_locate_file(const QwZipArchive *archive, const char *name,
                              const char *file_to_match, unsigned flags)
{
    size_t i;
    size_t name_size;
    int case_sensitive = (flags & QW_ZIP_CASE_SENSITIVE) != 0;
    (void)file_to_match;
    if (!archive || !name) return -1;
    name_size = strlen(name);
    for (i = 0; i < archive->count && i <= INT_MAX; ++i) {
        const QwZipEntry *entry = &archive->entries[i];
        size_t j;
        if (entry->name_size != name_size) continue;
        for (j = 0; j < name_size; ++j) {
            unsigned char left = (unsigned char)entry->name[j];
            unsigned char right = (unsigned char)name[j];
            if (case_sensitive ? left != right :
                qw_ascii_lower(left) != qw_ascii_lower(right)) break;
        }
        if (j == name_size) return (int)i;
    }
    return -1;
}

static uint32_t crc32_update_byte(uint32_t crc, uint8_t value)
{
    unsigned bit;
    crc ^= value;
    for (bit = 0; bit < 8u; ++bit) {
        crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)-(int32_t)(crc & 1u));
    }
    return crc;
}

typedef struct QwZipCrypto {
    uint32_t key0;
    uint32_t key1;
    uint32_t key2;
} QwZipCrypto;

static void zipcrypto_update(QwZipCrypto *crypto, uint8_t plain)
{
    crypto->key0 = crc32_update_byte(crypto->key0, plain);
    crypto->key1 = (crypto->key1 + (crypto->key0 & 0xffu)) *
                   134775813u + 1u;
    crypto->key2 = crc32_update_byte(crypto->key2,
                                     (uint8_t)(crypto->key1 >> 24));
}

static void zipcrypto_init(QwZipCrypto *crypto, const char *password)
{
    const unsigned char *p = (const unsigned char *)password;
    crypto->key0 = 0x12345678u;
    crypto->key1 = 0x23456789u;
    crypto->key2 = 0x34567890u;
    while (*p) zipcrypto_update(crypto, *p++);
}

static uint8_t zipcrypto_decrypt_byte(QwZipCrypto *crypto, uint8_t cipher)
{
    uint32_t temp = crypto->key2 | 2u;
    uint8_t plain = (uint8_t)(cipher ^
        (uint8_t)((temp * (temp ^ 1u)) >> 8));
    zipcrypto_update(crypto, plain);
    return plain;
}

static uint32_t zip_crc32(const uint8_t *data, size_t size)
{
    return qw_zip_crc32(data, size);
}

static int zip_inflate_raw(const uint8_t *input, size_t input_size,
                           uint8_t *output, size_t output_size)
{
    return qw_zip_inflate_raw(input, input_size, output, output_size);
}

void *qw_zip_reader_extract_to_heap_with_password(QwZipArchive *archive,
                                                  size_t index,
                                                  size_t *out_size,
                                                  const char *password)
{
    const QwZipEntry *entry;
    const uint8_t *compressed;
    uint64_t data_offset;
    uint16_t local_name_size;
    uint16_t local_extra_size;
    size_t compressed_size;
    size_t output_size;
    uint8_t *decrypted = NULL;
    const uint8_t *payload;
    uint8_t *output;

    if (out_size) *out_size = 0u;
    if (!archive || index >= archive->count) return NULL;
    entry = &archive->entries[index];
    if (!qw_zip_reader_is_file_supported(archive, index) ||
        entry->compressed_size > SIZE_MAX ||
        entry->uncompressed_size > SIZE_MAX) {
        archive->error = "unsupported ZIP compression method or entry size";
        return NULL;
    }
    if (entry->uncompressed_size > archive->max_single_expanded_bytes) {
        archive->error = "ZIP entry exceeds its expanded-size resource limit";
        return NULL;
    }
    if ((entry->flags & ZIP_FLAG_ENCRYPTED) &&
        (entry->flags & ZIP_FLAG_STRONG_ENCRYPTION)) {
        archive->error = "strong ZIP encryption is unsupported";
        return NULL;
    }
    if ((entry->flags & ZIP_FLAG_ENCRYPTED) && !password) {
        archive->error = "ZIP entry requires a password";
        return NULL;
    }
    if (!range_valid(archive->size, entry->local_header_offset,
                     ZIP_LOCAL_SIZE)) {
        archive->error = "ZIP local file header is outside the input";
        return NULL;
    }
    {
        const uint8_t *local = archive->data +
                               (size_t)entry->local_header_offset;
        if (qw_read_u32_le(local) != ZIP_LOCAL_SIGNATURE ||
            qw_read_u16_le(local + 8u) != entry->method ||
            ((qw_read_u16_le(local + 6u) ^ entry->flags) &
             ZIP_FLAG_ENCRYPTED) != 0u) {
            archive->error = "invalid ZIP local file header";
            return NULL;
        }
        local_name_size = qw_read_u16_le(local + 26u);
        local_extra_size = qw_read_u16_le(local + 28u);
        if (!range_valid(archive->size, entry->local_header_offset,
                         ZIP_LOCAL_SIZE + (uint64_t)local_name_size +
                         (uint64_t)local_extra_size) ||
            local_name_size != entry->name_size ||
            memcmp(local + ZIP_LOCAL_SIZE, entry->name,
                   local_name_size) != 0) {
            archive->error = "ZIP local and central entry names do not match";
            return NULL;
        }
    }
    data_offset = entry->local_header_offset + ZIP_LOCAL_SIZE +
                  (uint64_t)local_name_size + (uint64_t)local_extra_size;
    if (!range_valid(archive->size, data_offset, entry->compressed_size)) {
        archive->error = "ZIP compressed entry is outside the input";
        return NULL;
    }
    compressed = archive->data + (size_t)data_offset;
    compressed_size = (size_t)entry->compressed_size;
    payload = compressed;
    if (entry->flags & ZIP_FLAG_ENCRYPTED) {
        QwZipCrypto crypto;
        uint8_t check_byte;
        size_t i;
        if (compressed_size < 12u) {
            archive->error = "truncated traditional ZIP encryption header";
            return NULL;
        }
        decrypted = (uint8_t *)malloc(compressed_size);
        if (!decrypted) {
            archive->error = "out of memory for encrypted ZIP entry";
            return NULL;
        }
        zipcrypto_init(&crypto, password);
        for (i = 0; i < 12u; ++i) {
            decrypted[i] = zipcrypto_decrypt_byte(&crypto, compressed[i]);
        }
        check_byte = (entry->flags & 8u)
            ? (uint8_t)(entry->dos_time >> 8)
            : (uint8_t)(entry->crc32 >> 24);
        if (decrypted[11] != check_byte) {
            free(decrypted);
            archive->error = "ZIP password is incorrect";
            return NULL;
        }
        for (i = 12u; i < compressed_size; ++i) {
            decrypted[i] = zipcrypto_decrypt_byte(&crypto, compressed[i]);
        }
        payload = decrypted + 12u;
        compressed_size -= 12u;
    }

    output_size = (size_t)entry->uncompressed_size;
    output = (uint8_t *)malloc(output_size ? output_size : 1u);
    if (!output) {
        free(decrypted);
        archive->error = "out of memory for extracted ZIP entry";
        return NULL;
    }
    if (entry->method == ZIP_METHOD_STORE) {
        if (compressed_size != output_size) {
            free(output);
            free(decrypted);
            archive->error = "stored ZIP entry has inconsistent sizes";
            return NULL;
        }
        if (output_size) memcpy(output, payload, output_size);
    } else if (!zip_inflate_raw(payload, compressed_size, output,
                                output_size)) {
        free(output);
        free(decrypted);
        archive->error = "could not inflate ZIP entry";
        return NULL;
    }
    free(decrypted);
    if (zip_crc32(output, output_size) != entry->crc32) {
        free(output);
        archive->error = "ZIP entry CRC does not match";
        return NULL;
    }
    archive->error = NULL;
    if (out_size) *out_size = output_size;
    return output;
}

void *qw_zip_reader_extract_to_heap(QwZipArchive *archive, size_t index,
                                    size_t *out_size, unsigned flags)
{
    (void)flags;
    return qw_zip_reader_extract_to_heap_with_password(archive, index,
                                                       out_size, NULL);
}

const char *qw_zip_archive_error(const QwZipArchive *archive)
{
    return archive && archive->error ? archive->error : "no ZIP error";
}

static int writer_reserve(QwZipWriter *writer, size_t additional)
{
    size_t needed;
    size_t capacity;
    uint8_t *data;
    if (additional > SIZE_MAX - writer->size) return 0;
    needed = writer->size + additional;
    if (needed <= writer->capacity) return 1;
    capacity = writer->capacity ? writer->capacity : 256u;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2u) {
            capacity = needed;
            break;
        }
        capacity *= 2u;
    }
    data = (uint8_t *)realloc(writer->data, capacity);
    if (!data) return 0;
    writer->data = data;
    writer->capacity = capacity;
    return 1;
}

static int writer_reserve_entry(QwZipWriter *writer)
{
    size_t capacity;
    QwZipWriterEntry *entries;
    if (writer->count < writer->entry_capacity) return 1;
    capacity = writer->entry_capacity ? writer->entry_capacity * 2u : 16u;
    if (capacity < writer->entry_capacity ||
        capacity > SIZE_MAX / sizeof(*entries)) return 0;
    entries = (QwZipWriterEntry *)realloc(writer->entries,
                                          capacity * sizeof(*entries));
    if (!entries) return 0;
    writer->entries = entries;
    writer->entry_capacity = capacity;
    return 1;
}

int qw_zip_writer_init_heap(QwZipWriter *writer,
                            size_t size_to_reserve_at_beginning,
                            size_t initial_allocation_size)
{
    size_t initial;
    if (!writer) return 0;
    memset(writer, 0, sizeof(*writer));
    initial = initial_allocation_size > size_to_reserve_at_beginning
        ? initial_allocation_size : size_to_reserve_at_beginning;
    if (initial) {
        writer->data = (uint8_t *)malloc(initial);
        if (!writer->data) return 0;
        writer->capacity = initial;
        if (size_to_reserve_at_beginning) {
            memset(writer->data, 0, size_to_reserve_at_beginning);
            writer->size = size_to_reserve_at_beginning;
        }
    }
    return 1;
}

static int writer_name_valid(const char *name, size_t name_size)
{
    size_t i;
    if (!name || !name_size || name_size > UINT16_MAX ||
        name[0] == '/' || name[0] == '\\') return 0;
    for (i = 0; i < name_size; ++i) {
        if (name[i] == '\\' || name[i] == ':') return 0;
    }
    return 1;
}

int qw_zip_writer_add_mem(QwZipWriter *writer, const char *archive_name,
                          const void *data, size_t size, int compression_level)
{
    const uint8_t *input = (const uint8_t *)data;
    uint8_t *compressed = NULL;
    const uint8_t *payload = input;
    size_t payload_size = size;
    size_t name_size;
    size_t record_size;
    uint16_t method = ZIP_METHOD_STORE;
    uint8_t *header;
    char *name_copy;
    uint32_t crc;
    QwZipWriterEntry *entry;

    if (!writer || writer->finalized || writer->failed || !archive_name ||
        (!data && size) || size > UINT32_MAX) return 0;
    name_size = strlen(archive_name);
    if (!writer_name_valid(archive_name, name_size) ||
        !writer_reserve_entry(writer)) {
        writer->failed = 1;
        return 0;
    }
    if (compression_level != QW_ZIP_NO_COMPRESSION && size) {
        if (!qw_zip_deflate_raw_stored(input, size, &compressed,
                                       &payload_size)) {
            writer->failed = 1;
            return 0;
        }
        payload = compressed;
        method = ZIP_METHOD_DEFLATE;
    }
    if (payload_size > UINT32_MAX || writer->size > UINT32_MAX ||
        payload_size > SIZE_MAX - ZIP_LOCAL_SIZE ||
        name_size > SIZE_MAX - ZIP_LOCAL_SIZE - payload_size) {
        free(compressed);
        writer->failed = 1;
        return 0;
    }
    record_size = ZIP_LOCAL_SIZE + name_size + payload_size;
    if (!writer_reserve(writer, record_size)) {
        free(compressed);
        writer->failed = 1;
        return 0;
    }
    name_copy = (char *)malloc(name_size + 1u);
    if (!name_copy) {
        free(compressed);
        writer->failed = 1;
        return 0;
    }
    memcpy(name_copy, archive_name, name_size + 1u);
    crc = zip_crc32(input, size);
    entry = &writer->entries[writer->count];
    memset(entry, 0, sizeof(*entry));
    entry->name = name_copy;
    entry->name_size = name_size;
    entry->compressed_size = payload_size;
    entry->uncompressed_size = size;
    entry->local_header_offset = writer->size;
    entry->crc32 = crc;
    entry->method = method;

    header = writer->data + writer->size;
    memset(header, 0, ZIP_LOCAL_SIZE);
    qw_write_u32_le(header, ZIP_LOCAL_SIGNATURE);
    qw_write_u16_le(header + 4u, 20u);
    qw_write_u16_le(header + 6u, ZIP_FLAG_UTF8);
    qw_write_u16_le(header + 8u, method);
    qw_write_u32_le(header + 14u, crc);
    qw_write_u32_le(header + 18u, (uint32_t)payload_size);
    qw_write_u32_le(header + 22u, (uint32_t)size);
    qw_write_u16_le(header + 26u, (uint16_t)name_size);
    memcpy(header + ZIP_LOCAL_SIZE, archive_name, name_size);
    if (payload_size) {
        memcpy(header + ZIP_LOCAL_SIZE + name_size, payload, payload_size);
    }
    writer->size += record_size;
    ++writer->count;
    free(compressed);
    return 1;
}

int qw_zip_writer_finalize_heap_archive(QwZipWriter *writer,
                                        void **out_data, size_t *out_size)
{
    size_t i;
    size_t directory_start;
    size_t directory_size;
    uint8_t *header;
    if (!out_data || !out_size) return 0;
    *out_data = NULL;
    *out_size = 0u;
    if (!writer || writer->failed || writer->finalized ||
        writer->count > UINT16_MAX || writer->size > UINT32_MAX) return 0;
    directory_start = writer->size;
    for (i = 0; i < writer->count; ++i) {
        QwZipWriterEntry *entry = &writer->entries[i];
        size_t record_size = ZIP_CENTRAL_SIZE + entry->name_size;
        if (entry->local_header_offset > UINT32_MAX ||
            entry->compressed_size > UINT32_MAX ||
            entry->uncompressed_size > UINT32_MAX ||
            !writer_reserve(writer, record_size)) {
            writer->failed = 1;
            return 0;
        }
        header = writer->data + writer->size;
        memset(header, 0, ZIP_CENTRAL_SIZE);
        qw_write_u32_le(header, ZIP_CENTRAL_SIGNATURE);
        qw_write_u16_le(header + 4u, (uint16_t)((3u << 8) | 20u));
        qw_write_u16_le(header + 6u, 20u);
        qw_write_u16_le(header + 8u, ZIP_FLAG_UTF8);
        qw_write_u16_le(header + 10u, entry->method);
        qw_write_u32_le(header + 16u, entry->crc32);
        qw_write_u32_le(header + 20u, (uint32_t)entry->compressed_size);
        qw_write_u32_le(header + 24u, (uint32_t)entry->uncompressed_size);
        qw_write_u16_le(header + 28u, (uint16_t)entry->name_size);
        qw_write_u32_le(header + 38u, 0x81a40000u);
        qw_write_u32_le(header + 42u, (uint32_t)entry->local_header_offset);
        memcpy(header + ZIP_CENTRAL_SIZE, entry->name, entry->name_size);
        writer->size += record_size;
    }
    directory_size = writer->size - directory_start;
    if (directory_start > UINT32_MAX || directory_size > UINT32_MAX ||
        !writer_reserve(writer, ZIP_EOCD_SIZE)) {
        writer->failed = 1;
        return 0;
    }
    header = writer->data + writer->size;
    memset(header, 0, ZIP_EOCD_SIZE);
    qw_write_u32_le(header, ZIP_EOCD_SIGNATURE);
    qw_write_u16_le(header + 8u, (uint16_t)writer->count);
    qw_write_u16_le(header + 10u, (uint16_t)writer->count);
    qw_write_u32_le(header + 12u, (uint32_t)directory_size);
    qw_write_u32_le(header + 16u, (uint32_t)directory_start);
    writer->size += ZIP_EOCD_SIZE;
    writer->finalized = 1;
    *out_data = writer->data;
    *out_size = writer->size;
    writer->data = NULL;
    writer->size = 0u;
    writer->capacity = 0u;
    return 1;
}

void qw_zip_writer_end(QwZipWriter *writer)
{
    size_t i;
    if (!writer) return;
    for (i = 0; i < writer->count; ++i) free(writer->entries[i].name);
    free(writer->entries);
    free(writer->data);
    memset(writer, 0, sizeof(*writer));
}
