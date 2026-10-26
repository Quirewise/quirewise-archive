#include "zip_deflate.h"

#include <stdlib.h>
#include <string.h>

enum { QW_DEFLATE_MAX_BITS = 15, QW_DEFLATE_BLOCK_SIZE = 65535 };

typedef struct QwDeflateBitReader {
    const uint8_t *data;
    size_t size;
    size_t bit_offset;
} QwDeflateBitReader;

typedef struct QwDeflateHuffman {
    uint16_t count[QW_DEFLATE_MAX_BITS + 1];
    uint16_t symbols[288];
    uint16_t symbol_count;
} QwDeflateHuffman;

static int read_bits(QwDeflateBitReader *reader, unsigned count,
                     uint32_t *out_value)
{
    uint32_t value = 0;
    unsigned i;
    if (!reader || !out_value || count > 24u ||
        reader->size > SIZE_MAX / 8u ||
        reader->bit_offset > reader->size * 8u ||
        count > reader->size * 8u - reader->bit_offset) {
        return 0;
    }
    for (i = 0; i < count; ++i) {
        size_t offset = reader->bit_offset++;
        value |= (uint32_t)((reader->data[offset >> 3] >> (offset & 7u)) & 1u)
                 << i;
    }
    *out_value = value;
    return 1;
}

static int build_huffman(QwDeflateHuffman *tree, const uint8_t *lengths,
                         size_t symbol_count, unsigned max_bits)
{
    uint16_t offsets[QW_DEFLATE_MAX_BITS + 1] = {0};
    int available = 1;
    size_t symbol;
    unsigned length;
    if (!tree || !lengths || symbol_count > 288u ||
        !max_bits || max_bits > QW_DEFLATE_MAX_BITS) {
        return 0;
    }
    memset(tree, 0, sizeof(*tree));
    tree->symbol_count = (uint16_t)symbol_count;
    for (symbol = 0; symbol < symbol_count; ++symbol) {
        if (lengths[symbol] > max_bits) return 0;
        ++tree->count[lengths[symbol]];
    }
    tree->count[0] = 0;
    for (length = 1; length <= max_bits; ++length) {
        available <<= 1;
        available -= tree->count[length];
        if (available < 0) return 0;
    }
    for (length = 1; length < max_bits; ++length) {
        offsets[length + 1u] =
            (uint16_t)(offsets[length] + tree->count[length]);
    }
    for (symbol = 0; symbol < symbol_count; ++symbol) {
        if (lengths[symbol]) {
            tree->symbols[offsets[lengths[symbol]]++] = (uint16_t)symbol;
        }
    }
    return 1;
}

static int decode_symbol(QwDeflateBitReader *reader,
                         const QwDeflateHuffman *tree,
                         unsigned max_bits, uint16_t *out_symbol)
{
    uint32_t code = 0;
    uint32_t first = 0;
    uint32_t index = 0;
    unsigned length;
    for (length = 1; length <= max_bits; ++length) {
        uint32_t bit;
        uint32_t count;
        if (!read_bits(reader, 1u, &bit)) return 0;
        code |= bit;
        count = tree->count[length];
        if (code >= first && code - first < count) {
            uint32_t symbol_index = index + code - first;
            if (symbol_index >= tree->symbol_count) return 0;
            *out_symbol = tree->symbols[symbol_index];
            return 1;
        }
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    return 0;
}

static int build_fixed_trees(QwDeflateHuffman *literal,
                             QwDeflateHuffman *distance)
{
    uint8_t literal_lengths[288];
    uint8_t distance_lengths[32];
    size_t i;
    for (i = 0; i <= 143u; ++i) literal_lengths[i] = 8u;
    for (; i <= 255u; ++i) literal_lengths[i] = 9u;
    for (; i <= 279u; ++i) literal_lengths[i] = 7u;
    for (; i < 288u; ++i) literal_lengths[i] = 8u;
    memset(distance_lengths, 5, sizeof(distance_lengths));
    return build_huffman(literal, literal_lengths, 288u, 15u) &&
           build_huffman(distance, distance_lengths, 32u, 15u);
}

static int build_dynamic_trees(QwDeflateBitReader *reader,
                               QwDeflateHuffman *literal,
                               QwDeflateHuffman *distance)
{
    static const uint8_t code_order[19] = {
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
    };
    uint8_t code_lengths[19] = {0};
    uint8_t lengths[288u + 32u];
    QwDeflateHuffman code_tree;
    uint32_t hlit, hdist, hclen, value;
    size_t total;
    size_t used = 0;
    unsigned i;
    if (!read_bits(reader, 5u, &hlit) || !read_bits(reader, 5u, &hdist) ||
        !read_bits(reader, 4u, &hclen)) return 0;
    hlit += 257u;
    hdist += 1u;
    hclen += 4u;
    if (hlit > 286u || hdist > 32u || hclen > 19u) return 0;
    for (i = 0; i < hclen; ++i) {
        if (!read_bits(reader, 3u, &value)) return 0;
        code_lengths[code_order[i]] = (uint8_t)value;
    }
    if (!build_huffman(&code_tree, code_lengths, 19u, 7u)) return 0;
    total = (size_t)(hlit + hdist);
    while (used < total) {
        uint16_t symbol;
        size_t repeat;
        uint8_t repeated_value;
        if (!decode_symbol(reader, &code_tree, 7u, &symbol)) return 0;
        if (symbol <= 15u) {
            lengths[used++] = (uint8_t)symbol;
            continue;
        }
        if (symbol == 16u) {
            if (!used || !read_bits(reader, 2u, &value)) return 0;
            repeat = (size_t)value + 3u;
            repeated_value = lengths[used - 1u];
        } else if (symbol == 17u) {
            if (!read_bits(reader, 3u, &value)) return 0;
            repeat = (size_t)value + 3u;
            repeated_value = 0u;
        } else if (symbol == 18u) {
            if (!read_bits(reader, 7u, &value)) return 0;
            repeat = (size_t)value + 11u;
            repeated_value = 0u;
        } else {
            return 0;
        }
        if (repeat > total - used) return 0;
        while (repeat--) lengths[used++] = repeated_value;
    }
    if (!lengths[256u] ||
        !build_huffman(literal, lengths, (size_t)hlit, 15u)) return 0;
    if (hdist == 1u && lengths[hlit] == 0u) {
        memset(distance, 0, sizeof(*distance));
        return 1;
    }
    return build_huffman(distance, lengths + hlit, (size_t)hdist, 15u);
}

static int inflate_codes(QwDeflateBitReader *reader,
                         const QwDeflateHuffman *literal,
                         const QwDeflateHuffman *distance,
                         uint8_t *output, size_t output_size,
                         size_t *output_offset)
{
    static const uint16_t length_base[29] = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27,
        31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
    };
    static const uint8_t length_extra[29] = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
        2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
    };
    static const uint16_t distance_base[30] = {
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129,
        193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
        6145, 8193, 12289, 16385, 24577
    };
    static const uint8_t distance_extra[30] = {
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
        6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
    };
    for (;;) {
        uint16_t symbol;
        uint32_t extra;
        if (!decode_symbol(reader, literal, 15u, &symbol)) return 0;
        if (symbol < 256u) {
            if (*output_offset >= output_size) return 0;
            output[(*output_offset)++] = (uint8_t)symbol;
            continue;
        }
        if (symbol == 256u) return 1;
        if (symbol < 257u || symbol > 285u) return 0;
        {
            unsigned length_index = (unsigned)symbol - 257u;
            size_t length = length_base[length_index];
            uint16_t distance_symbol;
            size_t back;
            size_t i;
            if (length_extra[length_index]) {
                if (!read_bits(reader, length_extra[length_index], &extra)) return 0;
                length += extra;
            }
            if (!decode_symbol(reader, distance, 15u, &distance_symbol) ||
                distance_symbol >= 30u) return 0;
            back = distance_base[distance_symbol];
            if (distance_extra[distance_symbol]) {
                if (!read_bits(reader, distance_extra[distance_symbol], &extra)) return 0;
                back += extra;
            }
            if (!back || back > *output_offset ||
                length > output_size - *output_offset) return 0;
            for (i = 0; i < length; ++i) {
                output[*output_offset] = output[*output_offset - back];
                ++*output_offset;
            }
        }
    }
}

uint32_t qw_zip_crc32(const uint8_t *data, size_t size)
{
    uint32_t crc = 0xffffffffu;
    size_t i;
    for (i = 0; i < size; ++i) {
        unsigned bit;
        crc ^= data[i];
        for (bit = 0; bit < 8u; ++bit) {
            crc = (crc >> 1) ^
                  (0xedb88320u & (uint32_t)-(int32_t)(crc & 1u));
        }
    }
    return ~crc;
}

int qw_zip_inflate_raw(const uint8_t *input, size_t input_size,
                       uint8_t *output, size_t output_size)
{
    QwDeflateBitReader reader;
    size_t output_offset = 0;
    int final_block = 0;
    if (!input || (!output && output_size) || input_size > SIZE_MAX / 8u) return 0;
    reader.data = input;
    reader.size = input_size;
    reader.bit_offset = 0;
    while (!final_block) {
        uint32_t final_value, type;
        if (!read_bits(&reader, 1u, &final_value) ||
            !read_bits(&reader, 2u, &type)) return 0;
        final_block = (int)final_value;
        if (type == 0u) {
            uint32_t length, inverse;
            reader.bit_offset = (reader.bit_offset + 7u) & ~(size_t)7u;
            if (!read_bits(&reader, 16u, &length) ||
                !read_bits(&reader, 16u, &inverse) ||
                (length ^ 0xffffu) != inverse ||
                length > output_size - output_offset ||
                (size_t)length > input_size - (reader.bit_offset >> 3)) return 0;
            if (length) {
                memcpy(output + output_offset,
                       input + (reader.bit_offset >> 3), (size_t)length);
            }
            output_offset += (size_t)length;
            reader.bit_offset += (size_t)length * 8u;
        } else if (type == 1u || type == 2u) {
            QwDeflateHuffman literal, distance;
            int trees_ok = type == 1u
                ? build_fixed_trees(&literal, &distance)
                : build_dynamic_trees(&reader, &literal, &distance);
            if (!trees_ok || !inflate_codes(&reader, &literal, &distance,
                                            output, output_size,
                                            &output_offset)) return 0;
        } else {
            return 0;
        }
    }
    return output_offset == output_size &&
           (reader.bit_offset + 7u) / 8u == input_size;
}

int qw_zip_deflate_raw_stored(const uint8_t *input, size_t input_size,
                              uint8_t **out_data, size_t *out_size)
{
    size_t block_count;
    size_t output_size;
    size_t source_offset = 0;
    size_t output_offset = 0;
    uint8_t *output;
    if (!out_data || !out_size || (!input && input_size)) return 0;
    *out_data = NULL;
    *out_size = 0;
    if (!input_size || input_size > SIZE_MAX - (QW_DEFLATE_BLOCK_SIZE - 1u)) return 0;
    block_count = (input_size + QW_DEFLATE_BLOCK_SIZE - 1u) /
                  QW_DEFLATE_BLOCK_SIZE;
    if (block_count > (SIZE_MAX - input_size) / 5u) return 0;
    output_size = input_size + block_count * 5u;
    output = (uint8_t *)malloc(output_size);
    if (!output) return 0;
    while (source_offset < input_size) {
        size_t block_size = input_size - source_offset;
        int final_block;
        uint16_t length;
        if (block_size > QW_DEFLATE_BLOCK_SIZE) block_size = QW_DEFLATE_BLOCK_SIZE;
        final_block = source_offset + block_size == input_size;
        length = (uint16_t)block_size;
        output[output_offset++] = (uint8_t)(final_block ? 1u : 0u);
        output[output_offset++] = (uint8_t)length;
        output[output_offset++] = (uint8_t)(length >> 8);
        {
            uint16_t inverse = (uint16_t)~length;
            output[output_offset++] = (uint8_t)inverse;
            output[output_offset++] = (uint8_t)(inverse >> 8);
        }
        memcpy(output + output_offset, input + source_offset, block_size);
        source_offset += block_size;
        output_offset += block_size;
    }
    *out_data = output;
    *out_size = output_size;
    return 1;
}
