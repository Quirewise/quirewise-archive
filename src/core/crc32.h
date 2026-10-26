#ifndef QUIREWISE_CRC32_H
#define QUIREWISE_CRC32_H

#include <stddef.h>
#include <stdint.h>

/* IEEE CRC-32 (reflected polynomial 0xedb88320). The update function accepts
 * and returns the un-finalized state so callers can checksum streamed data.
 */
static inline uint32_t qw_crc32_ieee_update(uint32_t crc,
                                            const uint8_t *bytes,
                                            size_t size)
{
    size_t index;

    for (index = 0u; index < size; ++index) {
        unsigned int bit;
        crc ^= bytes[index];
        for (bit = 0u; bit < 8u; ++bit) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1u) ^ (0xedb88320u & mask);
        }
    }
    return crc;
}

static inline uint32_t qw_crc32_ieee(const uint8_t *bytes, size_t size)
{
    return qw_crc32_ieee_update(UINT32_MAX, bytes, size) ^ UINT32_MAX;
}

#endif
