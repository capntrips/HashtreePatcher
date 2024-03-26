#pragma once

#include <cstring>

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/test/avb_unittest_util.h#35
// Encodes |len| bytes of |data| as a lower-case hex-string.
std::string mem_to_hexstring(const uint8_t* data, size_t len);

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