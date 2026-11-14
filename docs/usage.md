# quirewise-archive usage guide

Task-level workflows for `Quirewise::Archive`. The API lives in
`quirewise/archive.h`, `quirewise/rar.h` and `quirewise/seven_zip.h`.

## 1. Build and integrate

Install `QuirewiseRuntime` and `QuirewiseCompression` into a prefix first:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/path/to/quirewise/prefix
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix /path/to/quirewise/prefix
```

Consumer CMake:

```cmake
find_package(QuirewiseArchive CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE Quirewise::Archive)
```

Nothing needs runtime initialization; the package config resolves the private
Compression dependency.

## 2. Core model and ownership

The library is byte-buffer based; it never opens files and never rewrites
entry names.

| Object | Owner | Lifetime / release |
|---|---|---|
| container bytes | caller | ZIP: until `qw_zip_archive_close`; USTAR/RAR/7z: until the call returns |
| `QwZipArchiveReader *` | library | `qw_zip_archive_close` |
| `QwArchiveBuffer::data` | caller | `qw_archive_buffer_free` (not `free`) |
| `QwArchiveEntry::name_bytes` | reader | until `qw_zip_archive_close` |
| TAR/RAR visitor views | library | only during the callback |
| 7z `name` | library | from `begin` until that entry's `finish`; the `entry` token is yours |

Status success is always 0. Failures are negative for `QwArchiveStatus` and
`QwRarStatus` (plus `QW_RAR_STOPPED` = 1) and positive for `QwSevenZipStatus`;
section 7 lists every value.

## 3. List and extract ZIP entries

`qw_zip_archive_open` parses the central directory eagerly, so listing costs one
allocation per entry name and no decompression.

```c
#include <quirewise/archive.h>

#include <stdio.h>

int list_zip(const uint8_t *zip, size_t zip_size)
{
    QwZipArchiveReader *reader = NULL;
    const char *error = NULL;
    size_t count;
    size_t index;
    QwArchiveStatus status = qw_zip_archive_open(zip, zip_size, &reader,
                                                 &error);

    if (status != QW_ARCHIVE_OK) {
        fprintf(stderr, "open: %s (%s)\n", qw_archive_status_string(status),
                error ? error : "no detail");
        return 1;
    }
    count = qw_zip_archive_entry_count(reader);
    for (index = 0u; index < count; ++index) {
        QwArchiveEntry entry;
        QwArchiveBuffer buffer = {0};

        if (qw_zip_archive_get_entry(reader, index, &entry) != QW_ARCHIVE_OK)
            continue;
        if (entry.is_directory)
            continue;
        status = qw_zip_archive_extract(reader, index, NULL, &buffer);
        if (status != QW_ARCHIVE_OK) {
            fprintf(stderr, "extract %zu: %s (%s)\n", index,
                    qw_archive_status_string(status),
                    qw_zip_archive_last_error(reader));
        }
        /* entry.name_bytes/entry.name_size name it; buffer holds the bytes */
        qw_archive_buffer_free(&buffer);
    }
    qw_zip_archive_close(reader);
    return 0;
}
```

Directories and methods other than Stored (0) and Deflate (8) produce
`QW_ARCHIVE_ERR_UNSUPPORTED`; `QW_ARCHIVE_ERR_INDEX` means the index is out of
range.

A password is only needed when bytes are extracted: pass it as the third
argument of `qw_zip_archive_extract` (after the index). Opening, listing and
metadata work without it.

`NULL` means "no password". A wrong password fails with
`QW_ARCHIVE_ERR_EXTRACT` after the 12-byte header check byte is validated, so
you can retry without reopening. WinZip AES and other strong-encryption entries
report `QW_ARCHIVE_ERR_UNSUPPORTED` even with a password.

## 4. Walk a USTAR archive

`qw_tar_archive_visit_ustar` validates the `ustar` magic and every 512-byte
header checksum before calling you. Directories are skipped; regular files
(type `0`, `\0` or `7`) reach the visitor.

```c
#include <quirewise/archive.h>

#include <stdio.h>
#include <string.h>

static QwArchiveTarVisitAction visit(void *context, const char *name,
                                     const uint8_t *data, size_t size)
{
    size_t *bytes = (size_t *)context;
    (void)data;
    *bytes += size;
    return strcmp(name, "README.md") == 0 ? QW_ARCHIVE_TAR_STOP
                                          : QW_ARCHIVE_TAR_CONTINUE;
}

size_t bytes = 0u;
QwArchiveStatus status = qw_tar_archive_visit_ustar(tar, tar_size, visit,
                                                    &bytes);
if (status != QW_ARCHIVE_OK)
    fprintf(stderr, "tar: %s\n", qw_archive_status_string(status));
```

`name` and `data` are valid only inside the callback. `QW_ARCHIVE_TAR_STOP`
finishes successfully with `QW_ARCHIVE_OK`; any other non-zero return value
aborts with `QW_ARCHIVE_ERR_CALLBACK`.

## 5. Read RAR metadata without decompressing

`qw_rar_archive_visit` parses RAR4 and RAR5 headers, verifies their CRCs and
hands you a view of each entry. Payload bytes are borrowed and never decoded.

```c
#include <quirewise/rar.h>

#include <stdio.h>

static QwRarVisitAction rar_visit(void *context, const QwRarEntryView *entry)
{
    unsigned long long *bytes = (unsigned long long *)context;
    if (!entry->is_directory)
        *bytes += (unsigned long long)entry->uncompressed_size;
    return QW_RAR_VISIT_CONTINUE; /* or QW_RAR_VISIT_STOP */
}

QwRarParseLimits limits = {4096u, 64ull << 20, 256ull << 20};
unsigned long long bytes = 0ull;
QwRarStatus status = qw_rar_archive_visit(rar, rar_size, &limits, rar_visit,
                                          &bytes);
if (status != QW_RAR_OK && status != QW_RAR_STOPPED)
    fprintf(stderr, "rar status %d\n", (int)status);
```

Pass `NULL` for `limits` to use the defaults (100,000 entries, 1 TiB per entry,
4 TiB total). Names are bytes, not guaranteed UTF-8: RAR4 Unicode names are
decoded to UTF-8, other RAR4 names keep their stored code page, and RAR5 names
are passed through as stored.

## 6. Probe and unpack a 7z archive

`qw_seven_zip_probe` validates the signature and both header CRCs without
decoding data. Extraction needs a sink; the folder is decoded into one
256 MiB-capped buffer before the first callback.

```c
#include <quirewise/seven_zip.h>

#include <stdio.h>

typedef struct Sink { unsigned long long bytes; } Sink;

static int seven_begin(void *context, uint32_t index, const char *name,
                       uint64_t declared_size, int is_directory,
                       void **out_entry)
{
    (void)index;
    printf("%s%s (%llu bytes)\n", name, is_directory ? "/" : "",
           (unsigned long long)declared_size);
    *out_entry = context; /* non-NULL enables write(); NULL skips data */
    return 0;             /* nonzero aborts with QW_SEVEN_ZIP_SINK_ERROR */
}

static int seven_write(void *context, void *entry, const void *data,
                       size_t size)
{
    (void)entry;
    (void)data; /* a chunk of at most 64 KiB: copy it out here */
    ((Sink *)context)->bytes += (unsigned long long)size;
    return 0;
}

static void seven_finish(void *context, void *entry, int result)
{
    (void)context;
    (void)entry;
    (void)result; /* nonzero: this entry failed */
}

Sink sink = {0ull};
QwSevenZipSink callbacks = {&sink, seven_begin, seven_write, seven_finish};
QwSevenZipStatus status = qw_seven_zip_probe(archive, archive_size, NULL);
if (status == QW_SEVEN_ZIP_OK)
    status = qw_seven_zip_extract(archive, archive_size, NULL, &callbacks);
if (status != QW_SEVEN_ZIP_OK)
    fprintf(stderr, "7z: %d\n", (int)status);
```

`begin` runs once per entry, including directories; `write` receives the bytes
in order; `finish` always runs after `begin`, with 0 on success, the value
returned by `begin`, or 1 after a failing `write`. A non-empty `password` is
rejected with `QW_SEVEN_ZIP_UNSUPPORTED`. A resource-limit failure arrives
before any callback; `SINK_ERROR` can leave partial output behind. `probe` also
accepts a non-NULL `size_t *` for the header offset.

## 7. Status values and error handling

`QwArchiveStatus` (`quirewise/archive.h`):

| Value | Meaning |
|---|---|
| `QW_ARCHIVE_OK` = 0 | success |
| `QW_ARCHIVE_ERR_INVALID_ARGUMENT` = -1 | NULL pointer, empty input, bad format |
| `QW_ARCHIVE_ERR_OUT_OF_MEMORY` = -2 | allocation failed |
| `QW_ARCHIVE_ERR_OPEN` = -3 | the ZIP could not be opened |
| `QW_ARCHIVE_ERR_UNSUPPORTED` = -4 | directory, unsupported method or encryption |
| `QW_ARCHIVE_ERR_EXTRACT` = -5 | entry data could not be decoded or verified |
| `QW_ARCHIVE_ERR_INDEX` = -6 | entry index out of range |
| `QW_ARCHIVE_ERR_CALLBACK` = -7 | TAR visitor returned an unexpected value |
| `QW_ARCHIVE_ERR_FORMAT` = -8 | structurally invalid archive |
| `QW_ARCHIVE_ERR_RESOURCE_LIMIT` = -9 | a fixed input/entry/total limit was hit |

`QwRarStatus` uses `QW_RAR_OK` = 0, `QW_RAR_STOPPED` = 1,
`QW_RAR_ERR_INVALID_ARGUMENT` = -1, `QW_RAR_ERR_OUT_OF_MEMORY` = -2,
`QW_RAR_ERR_FORMAT` = -4, `QW_RAR_ERR_UNSUPPORTED` = -5,
`QW_RAR_ERR_RESOURCE_LIMIT` = -11 and `QW_RAR_ERR_CALLBACK` = -100; the values
are not contiguous. `QwSevenZipStatus` is all non-negative:
`QW_SEVEN_ZIP_OK` = 0, `INVALID_ARGUMENT` = 1, `UNSUPPORTED` = 2,
`DECODE_ERROR` = 3, `RESOURCE_LIMIT` = 4, `SINK_ERROR` = 5,
`OUT_OF_MEMORY` = 6, `FORMAT_ERROR` = 7.

Practical rules:

- Branch on the enum, not on `status < 0`; 7z errors are positive.
- `qw_zip_archive_open` writes a static diagnostic to `out_error`;
  `qw_zip_archive_last_error` reports the latest one on a live reader
  (`"no ZIP error"` when none is set, NULL only for a NULL reader). Do not free
  either string, and do not use `qw_archive_status_string` for RAR/7z values.
- Outputs are reset before validation: `QwArchiveBuffer` is `{NULL, 0}` after a
  failed extract, and `QwArchiveEntry` is zeroed before a failed `get_entry`.

## 8. Memory, lifetime and threading

- The library allocates the entry table and the extracted buffer; it never
  allocates the input and retains no pointer after you close the reader.
- A ZIP reader holds the input pointer and a mutable error string, so one
  reader must not be used from two threads at once. Separate readers over
  separate buffers are fine; there are no locks and no global state.
- USTAR, RAR and 7z calls touch the input only for the call and run callbacks
  synchronously; 7z holds the decoded folder while the sink runs.

## 9. Limits and format notes

| Format | Enforced by | Limits |
|---|---|---|
| ZIP | fixed profile | 1 GiB input, 50,000 entries, 256 MiB per entry, 1 GiB total |
| USTAR | fixed profile | same as ZIP, plus 1 MiB per PAX/GNU extended header |
| RAR | `QwRarParseLimits` | defaults 100,000 entries, 1 TiB per entry, 4 TiB total |
| 7z | fixed | 256 MiB unpacked folder, 16 MiB next header, 4 coders |

- ZIP/USTAR: Stored and Deflate only, ZIP64 and data descriptors understood,
  local header must match the central directory, CRC-32 checked, multi-disk
  archives and names containing NUL rejected. USTAR requires the `ustar` magic,
  honours GNU `L` names and PAX `path`/`size`, and rejects sparse files.
- RAR: main and end headers must be present and CRC-valid; split, encrypted and
  multi-volume archives are rejected; payloads are never decompressed.
- 7z: one folder, one packed stream, linear coder chains (Copy, LZMA, LZMA2,
  Deflate, Delta, BCJ), no encryption, no external names, no PPMd or BZip2.
  Names are passed through verbatim; sanitize them before using them as paths.

## 10. Related packages

- `Quirewise::Compression` supplies the DEFLATE and 7z coders used internally.
- `Quirewise::Comic` builds CBZ/CBT page lists on top of this package, and
  `Quirewise::Ebook` uses the ZIP reader for HTMLZ/TXTZ containers.
- `Quirewise::Runtime` owns the shared status vocabulary and ABI helpers.

## 11. License

MIT. See `LICENSE`.
