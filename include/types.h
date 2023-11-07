#ifndef CHIA_TYPES_H
#define CHIA_TYPES_H

#include <cstdint>

#include <array>
#include <string>
#include <vector>

namespace chia
{

using Bytes = std::vector<uint8_t>;
using Bytes32 = std::array<uint8_t, 32>;
using Bytes48 = std::array<uint8_t, 48>;
using Bytes64 = std::array<uint8_t, 64>;
using Bytes96 = std::array<uint8_t, 96>;

using PrivateKey = Bytes32;
using PublicKey = Bytes48;
using Signature = Bytes96;
using Address = std::string;

} // namespace chia

#endif
