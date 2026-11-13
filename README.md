# quirewise-archive

Standalone C11 archive library for ZIP, TAR, RAR and 7z inspection.

CMake target: `Quirewise::Archive`.

## Capabilities

- **ZIP**: list and extract entries, including Stored/Deflate, ZIP64, CRC
  verification and traditional ZipCrypto. WinZip AES is not exposed.
- **TAR/USTAR**: streaming reader with checksum and entry-bound validation,
  GNU longname and PAX path/size support. No archive writing.
- **RAR4/RAR5**: header and entry **metadata** parsing only. Compressed entry
  payloads are borrowed from the archive and are not decompressed, so this
  package cannot extract CBR archives.
- **7z**: header parsing and bounded extraction through a caller sink for a
  single packed stream / single folder with a linear coder chain
  (Copy/LZMA/LZMA2/Deflate/Delta/BCJ). Encryption, PPMd, BZip2, multiple
  folders/streams and external file names are unsupported.

All readers enforce archive/entry count, expanded-size and input-size limits and
return explicit status codes. Archive writing is not part of this package.

## Build

```powershell
cmake -S . -B build
cmake --build build
ctest --test-dir build
cmake --install build --prefix install
```

Consumers use `find_package(QuirewiseArchive CONFIG REQUIRED)` and link
`Quirewise::Archive`. The package depends on `Quirewise::Runtime` (PUBLIC) and
`Quirewise::Compression` (PRIVATE).
