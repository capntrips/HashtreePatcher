#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <vector>
#include <utility>
#include <algorithm>
#include <cmath>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <libavb/libavb.h>
#include <fec/io.h>
#include <openssl/sha.h>
#include "hashtreepatcher.hpp"
#include "version.hpp"

int main(int argc, char **argv) {
    int fd_dlkm;
    int fd_vbmeta;
    int fd_fec;
    struct stat stat_dlkm; // NOLINT(cppcoreguidelines-pro-type-member-init)
    struct stat stat_vbmeta; // NOLINT(cppcoreguidelines-pro-type-member-init)
    struct stat stat_fec; // NOLINT(cppcoreguidelines-pro-type-member-init)
    void *addr_dlkm;
    void *addr_vbmeta;
    void *addr_fec;
    uint8_t *buf_dlkm;
    uint8_t *buf_vbmeta;
    uint8_t *buf_fec;

    if (argc != 3) {
        if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
            printf("%s %s\n", argv[0], version);
            exit(EXIT_SUCCESS);
        } else {
            fprintf(stderr, "%s <vendor_dlkm.img> <vbmeta.img>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // https://man7.org/linux/man-pages/man2/mmap.2.html#EXAMPLES
    fd_dlkm = open(argv[1], O_RDWR);
    if (fd_dlkm == -1) {
        fprintf(stderr, "! Unable to open %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    if (fstat(fd_dlkm, &stat_dlkm) == -1) {
        fprintf(stderr, "! Unable to fstat %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    addr_dlkm = mmap(nullptr, stat_dlkm.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_dlkm, 0);
    if (addr_dlkm == MAP_FAILED) {
        fprintf(stderr, "! Unable to mmap %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    fd_vbmeta = open(argv[2], O_RDWR);
    if (fd_vbmeta == -1) {
        fprintf(stderr, "! Unable to open %s\n", argv[2]);
        exit(EXIT_FAILURE);
    }

    if (fstat(fd_vbmeta, &stat_vbmeta) == -1) {
        fprintf(stderr, "! Unable to fstat %s\n", argv[2]);
        exit(EXIT_FAILURE);
    }

    addr_vbmeta = mmap(nullptr, stat_vbmeta.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_vbmeta, 0);
    if (addr_vbmeta == MAP_FAILED) {
        fprintf(stderr, "! Unable to mmap %s\n", argv[2]);
        exit(EXIT_FAILURE);
    }

    buf_dlkm = static_cast<uint8_t *>(addr_dlkm);
    buf_vbmeta = static_cast<uint8_t *>(addr_vbmeta);

    const uint8_t* header_block = buf_vbmeta;
    AvbVBMetaImageHeader vbmeta_header;
    size_t vbmeta_length;
    AvbHashtreeDescriptor* dlkm_desc_orig;
    AvbHashtreeDescriptor dlkm_desc;
    const uint8_t* dlkm_salt;
    const uint8_t* dlkm_digest;
    uint8_t digest_size;
    uint8_t digest_padding;
    uint64_t image_size = stat_dlkm.st_size;
    uint64_t combined_size = stat_dlkm.st_size;
    uint64_t tree_offset = stat_dlkm.st_size;
    uint16_t block_size = 4096;
    std::vector<uint32_t> hash_level_offsets;
    uint32_t tree_size;
    uint16_t tree_padding;
    uint32_t fec_offset = 0;
    std::vector<uint8_t> root_digest;
    std::vector<uint8_t> hash_tree;
    uint32_t fec_size = 0;
    uint16_t fec_padding = 0;
    uint32_t fec_num_roots = 0;

    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_vbmeta_image.c#63
    if (avb_safe_memcmp(header_block, AVB_MAGIC, AVB_MAGIC_LEN) != 0) {
        fprintf(stderr, "! Header magic is incorrect\n");
        exit(EXIT_FAILURE);
    }
    avb_vbmeta_image_header_to_host_byte_order((AvbVBMetaImageHeader*)(header_block), &vbmeta_header);

    vbmeta_length = sizeof(AvbVBMetaImageHeader) + vbmeta_header.authentication_data_block_size + vbmeta_header.auxiliary_data_block_size;

    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_slot_verify.c#940
    size_t num_descriptors;
    size_t n;
    bool dlkm_found = false;
    const AvbDescriptor** descriptors = avb_descriptor_get_all(buf_vbmeta, vbmeta_length, &num_descriptors);
    for (n = 0; n < num_descriptors; n++) {
        // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_hash_descriptor.c#34
        AvbDescriptor desc;
        if (!avb_descriptor_validate_and_byteswap(descriptors[n], &desc)) {
            fprintf(stderr, "! Descriptor is invalid\n");
            exit(EXIT_FAILURE);
        }
        switch (desc.tag) {
            case AVB_DESCRIPTOR_TAG_HASHTREE: {
                // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_slot_verify.c#1121
                AvbHashtreeDescriptor hashtree_desc;
                const uint8_t* desc_partition_name;
                if (!avb_hashtree_descriptor_validate_and_byteswap((AvbHashtreeDescriptor*)descriptors[n], &hashtree_desc)) {
                    fprintf(stderr, "! Hashtree descriptor is invalid\n");
                    exit(EXIT_FAILURE);
                }

                desc_partition_name = (const uint8_t*)descriptors[n] + sizeof(AvbHashtreeDescriptor);

                if (hashtree_desc.partition_name_len == 11 && strncmp((const char*)desc_partition_name, "vendor_dlkm", hashtree_desc.partition_name_len) == 0) {
                    dlkm_desc_orig = (AvbHashtreeDescriptor*)descriptors[n];
                    dlkm_desc = hashtree_desc;
                    dlkm_found = true;

                    dlkm_salt = desc_partition_name + hashtree_desc.partition_name_len;
                    dlkm_digest = dlkm_salt + hashtree_desc.salt_len;
                }
            } break;
        }
        if (dlkm_found) {
            break;
        }
    }
    if (!dlkm_found) {
        fprintf(stderr, "! vendor_dlkm descriptor missing\n");
        exit(EXIT_FAILURE);
    }

    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#3595
    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_slot_verify.c#1167
    if (avb_strcmp((const char*)dlkm_desc.hash_algorithm, "sha1") == 0) {
        digest_size = AVB_SHA1_DIGEST_SIZE;
    } else if (avb_strcmp((const char*)dlkm_desc.hash_algorithm, "sha256") == 0) {
        digest_size = AVB_SHA256_DIGEST_SIZE;
    } else if (avb_strcmp((const char*)dlkm_desc.hash_algorithm, "sha512") == 0) {
        digest_size = AVB_SHA512_DIGEST_SIZE;
    } else {
        fprintf(stderr, "! Unsupported hash algorithm\n");
        exit(EXIT_FAILURE);
    }

    digest_padding = round_to_pow2(digest_size) - digest_size;

    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#3630
    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#771
    if (image_size % block_size != 0) {
        fprintf(stderr, "! File size of %lu is not a multiple of the image block size %u\n", image_size, block_size);
        exit(EXIT_FAILURE);
    }

    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#3679
    auto calculated = calc_hash_level_offsets(image_size, block_size, digest_size + digest_padding);
    hash_level_offsets = calculated.first;
    tree_size = calculated.second;

    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#3691
    auto generated = generate_hash_tree(buf_dlkm, image_size, block_size, digest_size, dlkm_salt, dlkm_desc.salt_len, digest_padding, hash_level_offsets, tree_size);
    root_digest = generated.first;
    hash_tree = generated.second;

    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#3720
    tree_padding = round_to_multiple(tree_size, block_size) - tree_size;
    combined_size = tree_offset + tree_size + tree_padding;

    munmap(addr_dlkm, tree_offset);

    if (ftruncate64(fd_dlkm, combined_size) != 0) { // NOLINT(cppcoreguidelines-narrowing-conversions)
        fprintf(stderr, "! Unable to resize %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    addr_dlkm = mmap(nullptr, combined_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_dlkm, 0);
    if (addr_dlkm == MAP_FAILED) {
        fprintf(stderr, "! Unable to mmap %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    buf_dlkm = static_cast<uint8_t *>(addr_dlkm);
    memset(&buf_dlkm[tree_offset], 0, tree_size + tree_padding);
    memcpy(&buf_dlkm[tree_offset], hash_tree.data(), tree_size);

    bool try_fec = false;
    fd_fec = open("fec", O_RDONLY);
    if (fd_fec != -1) {
        if (fstat(fd_fec, &stat_fec) != -1) {
            try_fec = true;
        }
        close(fd_fec);
    }
    if (try_fec) {
        fec_offset = combined_size;
        const char *fec_filename = "fec.bin";

        // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#4023
        char command[256];
        sprintf(command, "./fec --encode --roots 2 \"%s\" %s > /dev/null 2>&1", argv[1], fec_filename);
        system(command);

        fd_fec = open(fec_filename, O_RDWR);
        if (fd_fec == -1) {
            fprintf(stderr, "! Unable to open %s\n", argv[1]);
            exit(EXIT_FAILURE);
        }

        if (fstat(fd_fec, &stat_fec) == -1) {
            fprintf(stderr, "! Unable to fstat %s\n", argv[1]);
            exit(EXIT_FAILURE);
        }

        addr_fec = mmap(nullptr, stat_fec.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_fec, 0);
        if (addr_fec == MAP_FAILED) {
            fprintf(stderr, "! Unable to mmap %s\n", argv[1]);
            exit(EXIT_FAILURE);
        }

        buf_fec = static_cast<uint8_t *>(addr_fec);

        auto *footer = reinterpret_cast<fec_header *>(&buf_fec[stat_fec.st_size - sizeof(fec_header)]);
        if (footer->magic != FEC_MAGIC) {
            fprintf(stderr, "! Header magic is incorrect\n");
            exit(EXIT_FAILURE);
        }

        fec_size = footer->fec_size;
        fec_num_roots = footer->roots;

        // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#4023
        fec_padding = round_to_multiple(fec_size, block_size) - fec_size;
        combined_size = fec_offset + fec_size + fec_padding;

        munmap(addr_dlkm, fec_offset);

        if (ftruncate64(fd_dlkm, combined_size) != 0) { // NOLINT(cppcoreguidelines-narrowing-conversions)
            fprintf(stderr, "! Unable to resize %s\n", argv[1]);
            exit(EXIT_FAILURE);
        }

        addr_dlkm = mmap(nullptr, combined_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_dlkm, 0);
        if (addr_dlkm == MAP_FAILED) {
            fprintf(stderr, "! Unable to mmap %s\n", argv[1]);
            exit(EXIT_FAILURE);
        }

        buf_dlkm = static_cast<uint8_t *>(addr_dlkm);
        memset(&buf_dlkm[fec_offset], 0, fec_size + fec_padding);
        memcpy(&buf_dlkm[fec_offset], buf_fec, fec_size);

        munmap(addr_fec, stat_fec.st_size);
        close(fd_fec);
        unlink(fec_filename);
    }

    dlkm_desc.image_size = image_size;
    dlkm_desc.tree_offset = tree_offset;
    dlkm_desc.tree_size = tree_size + tree_padding;
    dlkm_desc.fec_num_roots = fec_num_roots;
    dlkm_desc.fec_offset = fec_offset;
    dlkm_desc.fec_size = fec_size + fec_padding;
    avb_hashtree_descriptor_byteunswap((const AvbHashtreeDescriptor*)&dlkm_desc, dlkm_desc_orig);
    avb_memcpy((void *)dlkm_digest, root_digest.data(), root_digest.size());
    printf("- Patching complete\n");

    printf(""
           "    Hashtree descriptor:\n"
           "    Image Size:            %lu bytes\n"
           "    Tree Offset:           %lu\n"
           "    Tree Size:             %d bytes\n"
           "    Data Block Size:       %d bytes\n"
           "    Hash Block Size:       %d bytes\n"
           "    FEC num roots:         %d\n"
           "    FEC offset:            %lu\n"
           "    FEC size:              %lu bytes\n"
           "    Hash Algorithm:        %s\n"
           "    Partition Name:        vendor_dlkm\n"
           "    Salt:                  %s\n"
           "    Root Digest:           %s\n"
           "    Flags:                 %d\n",
           image_size, image_size, tree_size, block_size, block_size, dlkm_desc.fec_num_roots, dlkm_desc.fec_offset, dlkm_desc.fec_size, (const char *)dlkm_desc.hash_algorithm,
           mem_to_hexstring(dlkm_salt, dlkm_desc.salt_len).c_str(), mem_to_hexstring(root_digest.data(), root_digest.size()).c_str(), dlkm_desc.flags);

    munmap(addr_dlkm, combined_size);
    close(fd_dlkm);

    munmap(addr_vbmeta, stat_vbmeta.st_size);
    close(fd_vbmeta);

    exit(EXIT_SUCCESS);
}

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/test/avb_unittest_util.cc#29
std::string mem_to_hexstring(const uint8_t* data, size_t len) {
    std::string ret;
    char digits[17] = "0123456789abcdef";
    for (size_t n = 0; n < len; n++) {
        ret.push_back(digits[data[n] >> 4]);
        ret.push_back(digits[data[n] & 0x0f]);
    }
    return ret;
}

// https://android.googlesource.com/platform/system/core/+/refs/tags/android-12.0.0_r12/fs_mgr/libfs_avb/util.cpp#32
bool NibbleValue(const char& c, uint8_t* value) {
    switch (c) {
        case '0' ... '9':
            *value = c - '0';
            break;
        case 'a' ... 'f':
            *value = c - 'a' + 10;
            break;
        case 'A' ... 'F':
            *value = c - 'A' + 10;
            break;
        default:
            return false;
    }
    return true;
}

// https://android.googlesource.com/platform/system/core/+/refs/tags/android-12.0.0_r12/fs_mgr/libfs_avb/util.cpp#52
bool HexToBytes(uint8_t* bytes, size_t bytes_len, const std::string& hex) {
    if (hex.size() % 2 != 0) {
        return false;
    }
    if (hex.size() / 2 > bytes_len) {
        return false;
    }
    for (size_t i = 0, j = 0, n = hex.size(); i < n; i += 2, ++j) {
        uint8_t high;
        if (!NibbleValue(hex[i], &high)) {
            return false;
        }
        uint8_t low;
        if (!NibbleValue(hex[i + 1], &low)) {
            return false;
        }
        bytes[j] = (high << 4) | low;
    }
    return true;
}

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_descriptor.c#29
void avb_descriptor_byteunswap(const AvbDescriptor* src, AvbDescriptor* dest) {
    dest->tag = avb_htobe64(src->tag);
    dest->num_bytes_following = avb_htobe64(src->num_bytes_following);
}

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_hashtree_descriptor.c#28
void avb_hashtree_descriptor_byteunswap(const AvbHashtreeDescriptor* src, AvbHashtreeDescriptor* dest) {
    avb_memcpy(dest, src, sizeof(AvbHashtreeDescriptor));
    avb_descriptor_byteunswap((const AvbDescriptor*)src, (AvbDescriptor*)dest);
    dest->dm_verity_version = avb_htobe32(dest->dm_verity_version);
    dest->image_size = avb_htobe64(dest->image_size);
    dest->tree_offset = avb_htobe64(dest->tree_offset);
    dest->tree_size = avb_htobe64(dest->tree_size);
    dest->data_block_size = avb_htobe32(dest->data_block_size);
    dest->hash_block_size = avb_htobe32(dest->hash_block_size);
    dest->fec_num_roots = avb_htobe32(dest->fec_num_roots);
    dest->fec_offset = avb_htobe64(dest->fec_offset);
    dest->fec_size = avb_htobe64(dest->fec_size);
    dest->partition_name_len = avb_htobe32(dest->partition_name_len);
    dest->salt_len = avb_htobe32(dest->salt_len);
    dest->root_digest_len = avb_htobe32(dest->root_digest_len);
    dest->flags = avb_htobe32(dest->flags);
}

// https://stackoverflow.com/a/29389440/434343
uint8_t bit_length(uint32_t x) {
    uint8_t i;
    for (i = 0; x != 0; ++i) {
        x >>= 1;
    }
    return i;
}

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#220
uint8_t round_to_pow2(uint8_t number) {
    return (uint8_t)pow(2, bit_length(number - 1));
}

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#203
uint32_t round_to_multiple(uint32_t number, uint16_t size) {
    uint16_t remainder = number % size;
    if (remainder == 0) {
        return number;
    }
    return number + size - remainder;
}

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#3956
std::pair<std::vector<uint32_t>, uint32_t> calc_hash_level_offsets(uint32_t image_size, uint16_t block_size, uint8_t digest_size) {
    std::vector<uint32_t> level_offsets;
    std::vector<uint32_t> level_sizes;
    uint32_t tree_size = 0;
    uint8_t num_levels = 0;
    uint32_t size = image_size;
    while (size > block_size) {
        uint32_t num_blocks = (size + block_size - 1) / block_size;
        uint32_t level_size = round_to_multiple(num_blocks * digest_size, block_size);
        level_sizes.push_back(level_size);
        tree_size += level_size;
        num_levels += 1;
        size = level_size;
    }
    for (uint8_t n = 0; n < num_levels; ++n) {
        uint32_t offset = 0;
        for (uint8_t m = n + 1; m < num_levels; ++m) {
            offset += level_sizes[m];
        }
        level_offsets.push_back(offset);
    }
    return std::make_pair(level_offsets, tree_size);
}

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#4055
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_hash_tree(uint8_t *image, uint32_t image_size, uint16_t block_size, uint8_t digest_size, const uint8_t *salt, uint8_t salt_size, uint16_t digest_padding, std::vector<uint32_t> hash_level_offsets, uint32_t tree_size) {
    SHA_CTX sha_ctx;
    SHA256_CTX sha256_ctx;
    SHA512_CTX sha512_ctx;
    std::vector<uint8_t> root_digest(digest_size);
    std::vector<uint8_t> hash_ret(tree_size);
    std::vector<uint8_t> level_output;

    uint32_t hash_src_offset = 0;
    uint32_t hash_src_size = image_size;
    uint8_t level_num = 0;
    while (hash_src_size > block_size) {
        std::vector<uint8_t> level_output_list;
        uint32_t remaining = hash_src_size;
        while (remaining > 0) {
            uint32_t level_output_offset = level_output_list.size();
            level_output_list.resize(level_output_list.size() + digest_size + digest_padding, 0);
            // Only read from the file for the first level - for subsequent
            // levels, access the array we're building.
            std::vector<uint8_t> data;
            if (level_num == 0) {
                uint32_t offset = hash_src_offset + hash_src_size - remaining;
                uint32_t size = std::min(remaining, (uint32_t)block_size);
                data.resize(size);
                memcpy(data.data(), &image[offset], size);
            } else {
                uint32_t offset = hash_level_offsets[level_num - 1] + hash_src_size - remaining;
                data.resize(block_size);
                memcpy(data.data(), &hash_ret.data()[offset], block_size); // NOLINT(readability-simplify-subscript-expr)
            }
            switch (digest_size) {
                case AVB_SHA1_DIGEST_SIZE:
                    SHA1_Init(&sha_ctx);
                    SHA1_Update(&sha_ctx, salt, salt_size);
                    SHA1_Update(&sha_ctx, data.data(), data.size());
                    SHA1_Final(&level_output_list.data()[level_output_offset], &sha_ctx); // NOLINT(readability-simplify-subscript-expr)
                    break;
                case AVB_SHA256_DIGEST_SIZE:
                    SHA256_Init(&sha256_ctx);
                    SHA256_Update(&sha256_ctx, salt, salt_size);
                    SHA256_Update(&sha256_ctx, data.data(), data.size());
                    SHA256_Final(&level_output_list.data()[level_output_offset], &sha256_ctx); // NOLINT(readability-simplify-subscript-expr)
                    break;
                case AVB_SHA512_DIGEST_SIZE:
                    SHA512_Init(&sha512_ctx);
                    SHA512_Update(&sha512_ctx, salt, salt_size);
                    SHA512_Update(&sha512_ctx, data.data(), data.size());
                    SHA512_Final(&level_output_list.data()[level_output_offset], &sha512_ctx); // NOLINT(readability-simplify-subscript-expr)
                    break;
                default:
                    fprintf(stderr, "! Unknown digest type\n");
                    exit(EXIT_FAILURE);
            }
            remaining -= data.size();
        }
        level_output.clear();
        level_output.swap(level_output_list);
        uint16_t padding_needed = round_to_multiple(level_output.size(), block_size) - level_output.size();
        if (padding_needed != 0) {
            level_output.resize(level_output.size() + padding_needed, 0);
        }
        // Copy level-output into resulting tree.
        uint32_t offset = hash_level_offsets[level_num];
        memcpy(&hash_ret.data()[offset], level_output.data(), level_output.size()); // NOLINT(readability-simplify-subscript-expr)
        // Continue on to the next level.
        hash_src_size = level_output.size();
        level_num += 1;
    }
    switch (digest_size) {
        case AVB_SHA1_DIGEST_SIZE:
            SHA1_Init(&sha_ctx);
            SHA1_Update(&sha_ctx, salt, salt_size);
            SHA1_Update(&sha_ctx, level_output.data(), level_output.size());
            SHA1_Final(root_digest.data(), &sha_ctx);
            break;
        case AVB_SHA256_DIGEST_SIZE:
            SHA256_Init(&sha256_ctx);
            SHA256_Update(&sha256_ctx, salt, salt_size);
            SHA256_Update(&sha256_ctx, level_output.data(), level_output.size());
            SHA256_Final(root_digest.data(), &sha256_ctx);
            break;
        case AVB_SHA512_DIGEST_SIZE:
            SHA512_Init(&sha512_ctx);
            SHA512_Update(&sha512_ctx, salt, salt_size);
            SHA512_Update(&sha512_ctx, level_output.data(), level_output.size());
            SHA512_Final(root_digest.data(), &sha512_ctx);
            break;
        default:
            fprintf(stderr, "! Unknown digest type\n");
            exit(EXIT_FAILURE);
    }
    return std::make_pair(root_digest, hash_ret);
}