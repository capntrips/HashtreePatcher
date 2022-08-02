#pragma once

#include <cstring>

using android::fs_mgr::FstabEntry;

bool are_flags_disabled();
FstabEntry find_fstab_entry(char* partition_name);
static bool IsMountPointMounted(const std::string& mount_point);

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/test/avb_unittest_util.h#35
// Encodes |len| bytes of |data| as a lower-case hex-string.
std::string mem_to_hexstring(const uint8_t* data, size_t len);

// https://android.googlesource.com/platform/system/core/+/refs/tags/android-12.0.0_r12/fs_mgr/libfs_avb/util.h#55
bool NibbleValue(const char& c, uint8_t* value);

// https://android.googlesource.com/platform/system/core/+/refs/tags/android-12.0.0_r12/fs_mgr/libfs_avb/util.h#57
bool HexToBytes(uint8_t* bytes, size_t bytes_len, const std::string& hex);

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_descriptor.h#67
/* Copies |src| to |dest|, byte-unswapping fields in the
 * process if needed.
 *
 * Data following the struct is not copied.
 */
void avb_descriptor_byteunswap(const AvbDescriptor* src, AvbDescriptor* dest);

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_hashtree_descriptor.h#85
/* Copies |src| to |dest|, byte-unswapping fields in the
 * process if needed.
 *
 * Data following the struct is not copied.
 */
void avb_hashtree_descriptor_byteunswap(const AvbHashtreeDescriptor* src, AvbHashtreeDescriptor* dest);

// https://stackoverflow.com/a/29389440/434343
uint8_t bit_length(uint32_t x);

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#220
// Rounds a number up to the next power of 2.
// If |number| is already a power of 2 then |number| is
// returned. Otherwise the smallest power of 2 greater than |number|
// is returned.
uint8_t round_to_pow2(uint8_t number);

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#203
// Rounds a number up to nearest multiple of another number.
// If |number| is a multiple of |size|, returns |number|, otherwise
// returns |number| + |size|.
uint32_t round_to_multiple(uint32_t number, uint16_t size);

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#3956
// Calculate the offsets of all the hash-levels in a Merkle-tree.
// Returns an array of offsets and the size of the tree, in bytes.
std::pair<std::vector<uint32_t>, uint32_t> calc_hash_level_offsets(uint32_t image_size, uint16_t block_size, uint8_t digest_size);

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/avbtool.py#4055
// Generates a Merkle-tree for a file.
// Returns the top-level hash and hash-tree as bytes.
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_hash_tree(uint8_t *image, uint32_t image_size, uint16_t block_size, uint8_t digest_size, const uint8_t *salt, uint8_t salt_size, uint16_t digest_padding, std::vector<uint32_t> hash_level_offsets, uint32_t tree_size);