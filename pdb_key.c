#define _CRT_SECURE_NO_WARNINGS

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
typedef __int64 pdb_file_offset;
#define pdb_fseek _fseeki64
#define pdb_ftell _ftelli64
#else
typedef long pdb_file_offset;
#define pdb_fseek fseek
#define pdb_ftell ftell
#endif

enum pdb_key_result {
    PDB_KEY_OK = 0,
    PDB_KEY_INVALID_ARGUMENT = 1,
    PDB_KEY_IO_ERROR = 2,
    PDB_KEY_INVALID_PE = 3,
    PDB_KEY_NOT_FOUND = 4,
    PDB_KEY_BUFFER_TOO_SMALL = 5
};

struct pe_view {
    const uint8_t *data;
    size_t size;
    size_t sections_offset;
    uint16_t section_count;
    uint32_t size_of_headers;
    uint32_t debug_rva;
    uint32_t debug_size;
};

static int range_is_valid(size_t size, size_t offset, size_t length)
{
    return offset <= size && length <= size - offset;
}

static uint16_t read_u16(const uint8_t *data, size_t offset)
{
    return (uint16_t)((uint16_t)data[offset] | ((uint16_t)data[offset + 1] << 8));
}

static uint32_t read_u32(const uint8_t *data, size_t offset)
{
    return (uint32_t)data[offset] | ((uint32_t)data[offset + 1] << 8) |
           ((uint32_t)data[offset + 2] << 16) | ((uint32_t)data[offset + 3] << 24);
}

static int parse_pe_headers(const uint8_t *data, size_t size, struct pe_view *view)
{
    size_t pe_offset;
    size_t file_header_offset;
    size_t optional_header_offset;
    size_t section_bytes;
    uint16_t optional_header_size;
    uint16_t optional_magic;
    uint32_t directory_count;
    size_t directory_count_offset;
    size_t directories_offset;
    size_t debug_directory_offset;

    if (!range_is_valid(size, 0, 0x40) || data[0] != 'M' || data[1] != 'Z') {
        return PDB_KEY_INVALID_PE;
    }

    pe_offset = (size_t)read_u32(data, 0x3c);
    if (!range_is_valid(size, pe_offset, 24) || memcmp(data + pe_offset, "PE\0\0", 4) != 0) {
        return PDB_KEY_INVALID_PE;
    }

    file_header_offset = pe_offset + 4;
    view->section_count = read_u16(data, file_header_offset + 2);
    optional_header_size = read_u16(data, file_header_offset + 16);
    optional_header_offset = file_header_offset + 20;
    if (!range_is_valid(size, optional_header_offset, optional_header_size) ||
        optional_header_size < 64) {
        return PDB_KEY_INVALID_PE;
    }

    optional_magic = read_u16(data, optional_header_offset);
    if (optional_magic == 0x10b) {
        directory_count_offset = 92;
        directories_offset = 96;
    } else if (optional_magic == 0x20b) {
        directory_count_offset = 108;
        directories_offset = 112;
    } else {
        return PDB_KEY_INVALID_PE;
    }

    if (optional_header_size < directory_count_offset + 4) {
        return PDB_KEY_INVALID_PE;
    }
    directory_count = read_u32(data, optional_header_offset + directory_count_offset);
    if (directory_count <= 6) {
        return PDB_KEY_NOT_FOUND;
    }

    debug_directory_offset = directories_offset + 6 * 8;
    if (optional_header_size < debug_directory_offset + 8) {
        return PDB_KEY_INVALID_PE;
    }
    view->debug_rva = read_u32(data, optional_header_offset + debug_directory_offset);
    view->debug_size = read_u32(data, optional_header_offset + debug_directory_offset + 4);
    if (view->debug_rva == 0 || view->debug_size < 28) {
        return PDB_KEY_NOT_FOUND;
    }

    view->size_of_headers = read_u32(data, optional_header_offset + 60);
    view->sections_offset = optional_header_offset + optional_header_size;
    section_bytes = (size_t)view->section_count * 40;
    if (view->section_count == 0 ||
        section_bytes / 40 != view->section_count ||
        !range_is_valid(size, view->sections_offset, section_bytes)) {
        return PDB_KEY_INVALID_PE;
    }

    view->data = data;
    view->size = size;
    return PDB_KEY_OK;
}

static int rva_to_file_offset(const struct pe_view *view, uint32_t rva, size_t *file_offset)
{
    uint16_t index;

    if (rva < view->size_of_headers && (size_t)rva < view->size) {
        *file_offset = (size_t)rva;
        return 1;
    }

    for (index = 0; index < view->section_count; ++index) {
        size_t section_offset = view->sections_offset + (size_t)index * 40;
        uint32_t virtual_size = read_u32(view->data, section_offset + 8);
        uint32_t virtual_address = read_u32(view->data, section_offset + 12);
        uint32_t raw_size = read_u32(view->data, section_offset + 16);
        uint32_t raw_offset = read_u32(view->data, section_offset + 20);
        uint32_t mapped_size = virtual_size > raw_size ? virtual_size : raw_size;
        uint64_t section_end = (uint64_t)virtual_address + mapped_size;

        if ((uint64_t)rva >= virtual_address && (uint64_t)rva < section_end) {
            uint32_t delta = rva - virtual_address;
            uint64_t result = (uint64_t)raw_offset + delta;
            if (delta >= raw_size || result >= view->size) {
                return 0;
            }
            *file_offset = (size_t)result;
            return 1;
        }
    }

    return 0;
}

static int format_rsds_key(const uint8_t *record, char *key, size_t key_size)
{
    uint32_t data1 = read_u32(record, 4);
    uint16_t data2 = read_u16(record, 8);
    uint16_t data3 = read_u16(record, 10);
    uint32_t age = read_u32(record, 20);
    int written;

    written = snprintf(
        key,
        key_size,
        "%08" PRIX32 "%04" PRIX16 "%04" PRIX16
        "%02X%02X%02X%02X%02X%02X%02X%02X%" PRIX32,
        data1,
        data2,
        data3,
        (unsigned)record[12],
        (unsigned)record[13],
        (unsigned)record[14],
        (unsigned)record[15],
        (unsigned)record[16],
        (unsigned)record[17],
        (unsigned)record[18],
        (unsigned)record[19],
        age
    );
    if (written < 0 || (size_t)written >= key_size) {
        return PDB_KEY_BUFFER_TOO_SMALL;
    }
    return PDB_KEY_OK;
}

int pdb_key_from_pe_data(const void *pe_data, size_t pe_size, char *key, size_t key_size)
{
    const uint8_t *data = (const uint8_t *)pe_data;
    struct pe_view view;
    size_t debug_offset;
    size_t entry_count;
    size_t index;
    int result;

    if (data == NULL || key == NULL || key_size == 0) {
        return PDB_KEY_INVALID_ARGUMENT;
    }

    result = parse_pe_headers(data, pe_size, &view);
    if (result != PDB_KEY_OK) {
        return result;
    }
    if (!rva_to_file_offset(&view, view.debug_rva, &debug_offset) ||
        !range_is_valid(view.size, debug_offset, view.debug_size)) {
        return PDB_KEY_INVALID_PE;
    }

    entry_count = view.debug_size / 28;
    for (index = 0; index < entry_count; ++index) {
        size_t entry_offset = debug_offset + index * 28;
        uint32_t type = read_u32(data, entry_offset + 12);
        uint32_t record_size;
        uint32_t record_rva;
        uint32_t record_file_pointer;
        size_t record_offset;

        if (type != 2) {
            continue;
        }

        record_size = read_u32(data, entry_offset + 16);
        record_rva = read_u32(data, entry_offset + 20);
        record_file_pointer = read_u32(data, entry_offset + 24);
        if (record_size < 24) {
            continue;
        }

        if (record_file_pointer != 0) {
            record_offset = (size_t)record_file_pointer;
        } else if (!rva_to_file_offset(&view, record_rva, &record_offset)) {
            continue;
        }
        if (!range_is_valid(view.size, record_offset, record_size)) {
            continue;
        }
        if (memcmp(data + record_offset, "RSDS", 4) == 0) {
            return format_rsds_key(data + record_offset, key, key_size);
        }
    }

    return PDB_KEY_NOT_FOUND;
}

int pdb_key_from_pe_file(const char *path, char *key, size_t key_size)
{
    FILE *file;
    pdb_file_offset length;
    uint8_t *data;
    size_t bytes_read;
    int result;

    if (path == NULL || key == NULL || key_size == 0) {
        return PDB_KEY_INVALID_ARGUMENT;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return PDB_KEY_IO_ERROR;
    }
    if (pdb_fseek(file, 0, SEEK_END) != 0 || (length = pdb_ftell(file)) <= 0 ||
        (uintmax_t)length > SIZE_MAX || pdb_fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return PDB_KEY_IO_ERROR;
    }

    data = (uint8_t *)malloc((size_t)length);
    if (data == NULL) {
        fclose(file);
        return PDB_KEY_IO_ERROR;
    }
    bytes_read = fread(data, 1, (size_t)length, file);
    if (fclose(file) != 0 || bytes_read != (size_t)length) {
        free(data);
        return PDB_KEY_IO_ERROR;
    }

    result = pdb_key_from_pe_data(data, bytes_read, key, key_size);
    free(data);
    return result;
}

#ifndef PDB_KEY_NO_MAIN
static const char *result_message(int result)
{
    switch (result) {
    case PDB_KEY_INVALID_ARGUMENT:
        return "invalid argument";
    case PDB_KEY_IO_ERROR:
        return "unable to read input file";
    case PDB_KEY_INVALID_PE:
        return "invalid or unsupported PE file";
    case PDB_KEY_NOT_FOUND:
        return "RSDS PDB key not found";
    case PDB_KEY_BUFFER_TOO_SMALL:
        return "output buffer is too small";
    default:
        return "unknown error";
    }
}

int main(int argc, char **argv)
{
    char key[41];
    int result;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <pe-file>\n", argc > 0 ? argv[0] : "pdb_key");
        return PDB_KEY_INVALID_ARGUMENT;
    }

    result = pdb_key_from_pe_file(argv[1], key, sizeof(key));
    if (result != PDB_KEY_OK) {
        fprintf(stderr, "pdb_key: %s\n", result_message(result));
        return result;
    }

    puts(key);
    return PDB_KEY_OK;
}
#endif
