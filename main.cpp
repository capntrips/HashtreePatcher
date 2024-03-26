#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include <libavb/libavb.h>

#include "hashtreepatcher.hpp"
#include "version.hpp"

int main(int argc, char **argv) {
    char *command_name = argv[0];

    if (argc <= 1) {
        fprintf(stderr, "%s [-v|--version] [patch]\n", command_name);
        exit(EXIT_SUCCESS);
    } else if (argc == 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0)) {
        fprintf(stderr, "%s %s\n", command_name, version);
        exit(EXIT_SUCCESS);
    }

    if (strcmp(argv[1], "patch") == 0) {
        if (argc != 5) {
            fprintf(stderr, "%s patch <partition-name> <partition.img> <vbmeta.img>\n", command_name);
            exit(EXIT_FAILURE);
        }

        int fd_partition;
        int fd_vbmeta;
        struct stat stat_partition; // NOLINT(cppcoreguidelines-pro-type-member-init)
        struct stat stat_vbmeta; // NOLINT(cppcoreguidelines-pro-type-member-init)
        void *addr_partition;
        void *addr_vbmeta;
        uint8_t *buf_partition;
        uint8_t *buf_partition_footer;
        uint8_t *buf_vbmeta;

        auto partition_name = argv[2];
        auto partition_image = argv[3];
        auto vbmeta_image = argv[4];

        // https://man7.org/linux/man-pages/man2/mmap.2.html#EXAMPLES
        fd_partition = open(partition_image, O_RDWR | O_CLOEXEC);
        if (fd_partition == -1) {
            fprintf(stderr, "! Unable to open %s\n", partition_image);
            exit(EXIT_FAILURE);
        }

        if (fstat(fd_partition, &stat_partition) == -1) {
            fprintf(stderr, "! Unable to fstat %s\n", partition_image);
            exit(EXIT_FAILURE);
        }

        addr_partition = mmap(nullptr, stat_partition.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_partition, 0);
        if (addr_partition == MAP_FAILED) {
            fprintf(stderr, "! Unable to mmap %s\n", partition_image);
            exit(EXIT_FAILURE);
        }

        fd_vbmeta = open(vbmeta_image, O_RDWR | O_CLOEXEC);
        if (fd_vbmeta == -1) {
            fprintf(stderr, "! Unable to open %s\n", vbmeta_image);
            exit(EXIT_FAILURE);
        }

        if (fstat(fd_vbmeta, &stat_vbmeta) == -1) {
            fprintf(stderr, "! Unable to fstat %s\n", vbmeta_image);
            exit(EXIT_FAILURE);
        }

        addr_vbmeta = mmap(nullptr, stat_vbmeta.st_mode, PROT_READ | PROT_WRITE, MAP_SHARED, fd_vbmeta, 0);
        if (addr_vbmeta == MAP_FAILED) {
            fprintf(stderr, "! Unable to mmap %s\n", vbmeta_image);
            exit(EXIT_FAILURE);
        }

        buf_partition = static_cast<uint8_t *>(addr_partition);
        buf_partition_footer = buf_partition + stat_partition.st_size - AVB_FOOTER_SIZE;
        buf_vbmeta = static_cast<uint8_t *>(addr_vbmeta);

        const uint8_t* header_block = buf_vbmeta;
        AvbVBMetaImageHeader vbmeta_header;
        size_t vbmeta_length;
        AvbDescriptor desc;
        AvbHashtreeDescriptor* partition_desc_orig;
        AvbHashtreeDescriptor partition_desc;
        const uint8_t* desc_partition_name;
        const uint8_t* partition_salt;
        const uint8_t* partition_digest;

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
        bool partition_found = false;
        const AvbDescriptor** descriptors = avb_descriptor_get_all(buf_vbmeta, vbmeta_length, &num_descriptors);
        for (n = 0; n < num_descriptors; n++) {
            // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_hash_descriptor.c#34
            if (!avb_descriptor_validate_and_byteswap(descriptors[n], &desc)) {
                fprintf(stderr, "! Descriptor is invalid\n");
                exit(EXIT_FAILURE);
            }
            switch (desc.tag) {
                case AVB_DESCRIPTOR_TAG_HASHTREE: {
                    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_slot_verify.c#1121
                    AvbHashtreeDescriptor hashtree_desc;
                    if (!avb_hashtree_descriptor_validate_and_byteswap((AvbHashtreeDescriptor*)descriptors[n], &hashtree_desc)) {
                        fprintf(stderr, "! Hashtree descriptor is invalid\n");
                        exit(EXIT_FAILURE);
                    }

                    desc_partition_name = (const uint8_t*)descriptors[n] + sizeof(AvbHashtreeDescriptor);

                    if (hashtree_desc.partition_name_len == 11 && strncmp((const char*)desc_partition_name, partition_name, hashtree_desc.partition_name_len) == 0) {
                        partition_desc_orig = (AvbHashtreeDescriptor*)descriptors[n];
                        partition_desc = hashtree_desc;
                        partition_found = true;

                        partition_salt = desc_partition_name + hashtree_desc.partition_name_len;
                        partition_digest = partition_salt + hashtree_desc.salt_len;
                    }
                } break;
            }
            if (partition_found) {
                break;
            }
        }
        if (!partition_found) {
            fprintf(stderr, "! partition descriptor missing\n");
            exit(EXIT_FAILURE);
        }

        // https://cs.android.com/android/platform/superproject/+/android-13.0.0_r31:external/avb/libavb/avb_footer.c;l=38
        if (avb_safe_memcmp(buf_partition_footer, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) != 0) {
            avb_error("! Footer magic is incorrect\n");
            exit(EXIT_FAILURE);
        } else {
            AvbFooter vbmeta_footer;
            AvbHashtreeDescriptor nested_desc;
            const uint8_t* nested_salt;
            const uint8_t* nested_digest;

            // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_slot_verify.c#661
            if (!avb_footer_validate_and_byteswap((const AvbFooter*)buf_partition_footer, &vbmeta_footer)) {
                fprintf(stderr, "! Footer is invalid\n");
                exit(EXIT_FAILURE);
            }

            header_block = buf_partition + vbmeta_footer.vbmeta_offset;

            // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_vbmeta_image.c#63
            if (avb_safe_memcmp(header_block, AVB_MAGIC, AVB_MAGIC_LEN) != 0) {
                fprintf(stderr, "! Header magic is incorrect\n");
                exit(EXIT_FAILURE);
            }

            avb_vbmeta_image_header_to_host_byte_order((AvbVBMetaImageHeader*)(header_block), &vbmeta_header);
            vbmeta_length = sizeof(AvbVBMetaImageHeader) + vbmeta_header.authentication_data_block_size + vbmeta_header.auxiliary_data_block_size;

            if (vbmeta_length != vbmeta_footer.vbmeta_size) {
                fprintf(stderr, "! Vbmeta size mismatch\n");
                exit(EXIT_FAILURE);
            }

            descriptors = avb_descriptor_get_all(header_block, vbmeta_length, &num_descriptors);
            if (num_descriptors != 1) {
                fprintf(stderr, "! Unexpected descriptor count\n");
                exit(EXIT_FAILURE);
            }

            // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_hash_descriptor.c#34
            if (!avb_descriptor_validate_and_byteswap(descriptors[0], &desc)) {
                fprintf(stderr, "! Descriptor is invalid\n");
                exit(EXIT_FAILURE);
            }

            if (desc.tag != AVB_DESCRIPTOR_TAG_HASHTREE) {
                fprintf(stderr, "! Unexpected descriptor tag\n");
                exit(EXIT_FAILURE);
            }

            // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_slot_verify.c#1121
            if (!avb_hashtree_descriptor_validate_and_byteswap((AvbHashtreeDescriptor*)descriptors[0], &nested_desc)) {
                fprintf(stderr, "! Hashtree descriptor is invalid\n");
                exit(EXIT_FAILURE);
            }

            desc_partition_name = (const uint8_t*)descriptors[0] + sizeof(AvbHashtreeDescriptor);

            if (nested_desc.partition_name_len != strlen(partition_name) || strncmp((const char*)desc_partition_name, partition_name, nested_desc.partition_name_len) != 0) {
                fprintf(stderr, "! Unexpected descriptor name\n");
                exit(EXIT_FAILURE);
            }

            if (partition_desc.salt_len != nested_desc.salt_len) {
                fprintf(stderr, "! Unexpected salt length tag\n");
                exit(EXIT_FAILURE);
            }

            if (partition_desc.root_digest_len != nested_desc.root_digest_len) {
                fprintf(stderr, "! Unexpected digest length tag\n");
                exit(EXIT_FAILURE);
            }

            nested_salt = desc_partition_name + nested_desc.partition_name_len;
            nested_digest = nested_salt + nested_desc.salt_len;

            partition_desc.image_size = nested_desc.image_size;
            partition_desc.tree_offset = nested_desc.tree_offset;
            partition_desc.tree_size = nested_desc.tree_size;
            partition_desc.fec_num_roots = nested_desc.fec_num_roots;
            partition_desc.fec_offset = nested_desc.fec_offset;
            partition_desc.fec_size = nested_desc.fec_size;

            avb_memcpy((void *)partition_desc.hash_algorithm, nested_desc.hash_algorithm, sizeof nested_desc.hash_algorithm);

            avb_memcpy((void *)partition_salt, nested_salt, nested_desc.salt_len);
            avb_memcpy((void *)partition_digest, nested_digest, nested_desc.root_digest_len);
        }

        avb_hashtree_descriptor_byteunswap((const AvbHashtreeDescriptor*)&partition_desc, (AvbHashtreeDescriptor *)partition_desc_orig);
        printf("- Patching complete\n");

        printf(""
               "    Hashtree descriptor:\n"
               "      Version of dm-verity:  %d\n"
               "      Image Size:            %" PRIu64 " bytes\n"
               "      Tree Offset:           %" PRIu64 "\n"
               "      Tree Size:             %" PRIu64 " bytes\n"
               "      Data Block Size:       %d bytes\n"
               "      Hash Block Size:       %d bytes\n"
               "      FEC num roots:         %d\n"
               "      FEC offset:            %" PRIu64 "\n"
               "      FEC size:              %" PRIu64 " bytes\n"
               "      Hash Algorithm:        %s\n"
               "      Partition Name:        %s\n"
               "      Salt:                  %s\n"
               "      Root Digest:           %s\n"
               "      Flags:                 %d\n",
               partition_desc.dm_verity_version,
               partition_desc.image_size,
               partition_desc.tree_offset,
               partition_desc.tree_size,
               partition_desc.data_block_size,
               partition_desc.hash_block_size,
               partition_desc.fec_num_roots,
               partition_desc.fec_offset,
               partition_desc.fec_size,
               (const char *)partition_desc.hash_algorithm,
               partition_name,
               mem_to_hexstring(partition_salt, partition_desc.salt_len).c_str(),
               mem_to_hexstring(partition_digest, partition_desc.root_digest_len).c_str(),
               partition_desc.flags
        );

        munmap(addr_partition, stat_partition.st_size);
        close(fd_partition);

        munmap(addr_vbmeta, stat_vbmeta.st_mode);
        close(fd_vbmeta);

        exit(EXIT_SUCCESS);
    } else {
        fprintf(stderr, "%s [-v|--version] [patch]\n", command_name);
        exit(EXIT_FAILURE);
    }
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