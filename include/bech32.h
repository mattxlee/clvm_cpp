#ifndef CHIA_BECH32_H
#define CHIA_BECH32_H

#include <string>
#include <vector>

#include "int.h"

namespace chia
{
namespace bech32
{

Int Polymod(std::vector<Int> const& values);

std::vector<Int> HRPExpand(std::string hrp);

bool VerifyChecksum(std::string hrp, std::vector<Int> const& data);

std::vector<Int> CreateChecksum(std::string hrp, std::vector<Int> const& data);

std::string Strip(std::string_view str, char strip_ch = ' ');

std::string Encode(std::string hrp, std::vector<Int> const& data);

std::vector<Int> ConvertBits(std::vector<Int> const& data, int frombits, int tobits, bool pad = true);

} // namespace bech32
} // namespace chia

#endif
