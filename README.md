# quirewise-archive

In-memory ZIP, USTAR, RAR and 7z inspection for C: list and extract ZIP
entries, stream USTAR members, read RAR headers, and unpack simple 7z folders.

`Quirewise::Archive` is an independent, MIT-licensed C11 library, installed as
a CMake package that needs no Quirewise application code.

## What it does

- Opens a ZIP archive held in memory, lists its entries, and extracts single
  entries (Stored and Deflate, ZIP64, CRC-32 verified).
- Decrypts traditional ZipCrypto entries when a password is supplied.
- Streams regular files out of a USTAR archive through a callback, honouring
  GNU long names and the PAX `path` and `size` records.
- Visits RAR4 and RAR5 entry metadata (name, sizes, CRC, method, flags, solid)
  without decompressing payloads.
- Validates the 7z start header and unpacks a single-folder archive through a
  caller-provided sink.

It deliberately does **not** write archives, does not decompress RAR payloads
(so it cannot extract CBR), and rejects other ZIP methods, WinZip AES,
multi-disk sets, encrypted 7z, and 7z layouts with more than one folder.

## Requirements

- C11 compiler and CMake 3.21 or newer.
- The `QuirewiseRuntime` and `QuirewiseCompression` packages installed in a
  prefix that CMake can find; no third-party dependencies. Tests use CTest.

## Build, test and install

Install Runtime and Compression into the same prefix first, then:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/path/to/quirewise/prefix
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix /path/to/quirewise/prefix
```

Without `CMAKE_PREFIX_PATH`, configuring fails at
`find_package(QuirewiseCompression CONFIG REQUIRED)`. Shared builds are
available with `-DQUIREWISE_BUILD_SHARED=ON`.

## Use it from CMake

```cmake
find_package(QuirewiseArchive CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE Quirewise::Archive)
```

`Quirewise::Archive` propagates `Quirewise::Runtime`; `Quirewise::Compression`
is linked privately but resolved by the package config.

## Quick start

Read a ZIP file into memory, list it, and extract its first entry when that entry is a regular file:

```c
#include <quirewise/archive.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    QwZipArchiveReader *reader = NULL;
    const char *error = NULL;
    QwArchiveEntry entry;
    QwArchiveBuffer buffer = {0};
    QwArchiveStatus status;
    uint8_t *zip = NULL;
    size_t zip_size = 0u;
    FILE *file;
    long length;

    if (argc < 2) return 2;
    file = fopen(argv[1], "rb");
    if (!file) return 2;
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0 ||
        !(zip = (uint8_t *)malloc((size_t)length ? (size_t)length : 1u)) ||
        fread(zip, 1u, (size_t)length, file) != (size_t)length) {
        fclose(file);
        free(zip);
        return 2;
    }
    fclose(file);
    zip_size = (size_t)length;

    status = qw_zip_archive_open(zip, zip_size, &reader, &error);
    if (status != QW_ARCHIVE_OK) {
        fprintf(stderr, "open failed: %s (%s)\n",
                qw_archive_status_string(status), error ? error : "no detail");
        free(zip);
        return 1;
    }
    printf("%zu entries\n", qw_zip_archive_entry_count(reader));
    if (qw_zip_archive_get_entry(reader, 0u, &entry) == QW_ARCHIVE_OK &&
        !entry.is_directory && entry.name_bytes) {
        printf("first entry: %.*s (%llu bytes)\n", (int)entry.name_size,
               (const char *)entry.name_bytes,
               (unsigned long long)entry.uncompressed_size);
        status = qw_zip_archive_extract(reader, 0u, NULL, &buffer);
        if (status == QW_ARCHIVE_OK)
            printf("extracted %zu bytes\n", buffer.size);
        else
            fprintf(stderr, "extract failed: %s (%s)\n",
                    qw_archive_status_string(status),
                    qw_zip_archive_last_error(reader));
    }
    qw_archive_buffer_free(&buffer);
    qw_zip_archive_close(reader);
    free(zip); /* the reader borrowed this buffer until close */
    return 0;
}
```

## API overview

| Header | Purpose |
|---|---|
| `quirewise/archive.h` | ABI version, `QwArchiveStatus`, ZIP reader, USTAR visitor, buffers |
| `quirewise/rar.h` | `QwRarStatus`, `QwRarEntryView`, `QwRarParseLimits`, RAR visitor |
| `quirewise/seven_zip.h` | `QwSevenZipStatus`, `QwSevenZipSink`, 7z probe and extract |

| Task | Functions |
|---|---|
| Version and messages | `qw_archive_abi_version`, `qw_archive_status_string` |
| Open and close ZIP | `qw_zip_archive_open`, `qw_zip_archive_close` |
| Enumerate ZIP entries | `qw_zip_archive_entry_count`, `qw_zip_archive_get_entry` |
| Extract a ZIP entry | `qw_zip_archive_extract`, `qw_archive_buffer_free` |
| ZIP diagnostics | `qw_zip_archive_last_error` |
| Walk USTAR files | `qw_tar_archive_visit_ustar` |
| Read RAR metadata | `qw_rar_archive_visit` |
| Validate and unpack 7z | `qw_seven_zip_probe`, `qw_seven_zip_extract` |

## Behavior and limits

- Input bytes are borrowed, never copied. A ZIP reader keeps the pointer until
  `qw_zip_archive_close`; USTAR, RAR and 7z calls borrow only for the call.
- `qw_zip_archive_extract` allocates the result; release it with
  `qw_archive_buffer_free`, not `free`. `data` is NULL on failure.
- Entry names are borrowed bytes: use `name_size`; do not assume UTF-8 or a
  terminator. Names are never path-sanitized, since nothing touches the disk.
- `QW_ARCHIVE_TAR_STOP` and `QW_RAR_VISIT_STOP` end a walk successfully
  (`QW_ARCHIVE_OK`, `QW_RAR_STOPPED`); any other non-zero visitor result aborts
  with `QW_ARCHIVE_ERR_CALLBACK` / `QW_RAR_ERR_CALLBACK`.
- ZIP and USTAR limits are fixed: 1 GiB input, 50,000 entries, 256 MiB per
  expanded entry, 1 GiB total expanded. RAR uses `QwRarParseLimits` (defaults:
  100,000 entries, 1 TiB per entry, 4 TiB total). 7z decodes one folder of at
  most 256 MiB with at most four coders, so memory use scales with the
  unpacked size, not the archive size.

## Testing

`ctest` runs `archive_compression_migration` (ZIP round trip plus 7z
Deflate/LZMA1/LZMA2 known answers) and `quirewise_archive_fuzz_smoke` (200
mutated ZIP, RAR, TAR and 7z inputs per format, checking for crashes).

## Documentation

See [docs/usage.md](docs/usage.md) for task-oriented recipes: ZIP listing and
extraction, ZipCrypto passwords, USTAR walking, RAR metadata and 7z sinks.

## License

MIT. See [LICENSE](LICENSE).
