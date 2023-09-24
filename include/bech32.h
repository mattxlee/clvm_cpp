#ifndef CHIA_BECH32_H
#define CHIA_BECH32_H

#include <string>
#include <vector>

#include "int.h"
#include "types.h"

namespace chia
{
namespace bech32
{

Int Polymod(std::vector<Int> const& values);

std::vector<Int> HRPExpand(std::string_view hrp);

bool VerifyChecksum(std::string_view hrp, std::vector<Int> const& data);

std::vector<Int> CreateChecksum(std::string_view hrp, std::vector<Int> const& data);

std::string Strip(std::string_view str, char strip_ch = ' ');

std::string Encode(std::string_view hrp, std::vector<Int> const& data);

std::pair<std::string, Bytes> Decode(std::string_view bech_in, int max_length = 90);

std::vector<Int> ConvertBits(std::vector<Int> const& data, int frombits, int tobits, bool pad = true);

std::string EncodePuzzleHash(Bytes const& puzzle_hash, std::string_view prefix);

std::vector<Int> DecodePuzzleHash(std::string_view address);

} // namespace bech32
} // namespace chia

#endif
