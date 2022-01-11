#ifndef CHIA_BECH32_H
#define CHIA_BECH32_H

#include <string_view>
#include <vector>

namespace chia {
namespace bech32 {

int Polymod(std::vector<int> const& values);

std::vector<int> HRPExpand(std::string_view hrp);

bool VerifyChecksum(std::string_view hrp, std::vector<int> const& data);

std::vector<int> CreateChecksum(std::string_view hrp,
                                std::vector<int> const& data);

std::string Encode(std::string_view hrp, std::vector<int> const& data);

std::vector<int> ConvertBits(std::vector<int> const& data, int frombits,
                             int tobits, bool pad = true);

}  // namespace bech32
}  // namespace chia

#endif
