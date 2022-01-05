#ifndef CHIA_UTILS_H
#define CHIA_UTILS_H

#include "types.h"

namespace chia {
namespace utils {

template <int LEN>
Bytes bytes_cast(std::array<uint8_t, LEN> const& rhs) {
  Bytes bytes(LEN);
  memcpy(bytes.data(), rhs.data(), LEN);
  return bytes;
}

template <int LEN>
std::array<uint8_t, LEN> bytes_cast(Bytes const& rhs) {
  assert(rhs.size() == LEN);

  std::array<uint8_t, LEN> res;
  memcpy(res.data(), rhs.data(), LEN);
  return res;
}

}  // namespace utils

}  // namespace chia

#endif
