#ifndef CHIA_BECH32_H
#define CHIA_BECH32_H

#include <string_view>
#include <vector>

#include "int.h"

namespace chia
{
namespace bech32
{

Int Polymod(std::vector<Int> const& values);

std::vector<Int> HRPExpand(std::string_view hrp);

bool VerifyChecksum(std::string_view hrp, std::vector<Int> const& data);

std::vector<Int> CreateChecksum(std::string_view hrp, std::vector<Int> const& data);

std::string Encode(std::string_view hrp, std::vector<Int> const& data);

std::vector<Int> ConvertBits(std::vector<Int> const& data, int frombits, int tobits, bool pad = true);

} // namespace bech32
} // namespace chia

#endif
