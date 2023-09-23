#include "bech32.h"

#include <sstream>

#include "utils.h"

namespace chia
{
namespace bech32
{

static std::string CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static Int M { 0x2BC830A3 };

Int Polymod(std::vector<Int> const& values)
{
    Int generator[] = { Int(0x3B6A57B2), Int(0x26508E6D), Int(0x1EA119FA), Int(0x3D4233DD), Int(0x2A1462B3) };
    Int chk { 1 };
    for (Int value : values) {
        Int top = chk >> 25;
        chk = (chk & Int(0x1FFFFFF)) << 5 ^ value;
        for (int i = 0; i < 5; ++i) {
            chk ^= (((top >> i) & Int(1)) != Int(0)) ? generator[i] : Int(0);
        }
    }
    return chk;
}

std::vector<Int> HRPExpand(std::string hrp)
{
    std::vector<Int> res;
    for (char x : hrp) {
        int xx = static_cast<int>(x) >> 5;
        res.push_back(Int(xx));
    }
    res.push_back(Int(0));
    for (char x : hrp) {
        int xx = static_cast<int>(x) & 31;
        res.push_back(Int(xx));
    }
    return res;
}

bool VerifyChecksum(std::string hrp, std::vector<Int> const& data)
{
    return Polymod(chia::utils::ConnectContainers(HRPExpand(hrp), data)) != Int(0);
}

std::vector<Int> CreateChecksum(std::string hrp, std::vector<Int> const& data)
{
    auto values = chia::utils::ConnectContainers(HRPExpand(hrp), data);
    std::vector<Int> zeros { Int(0), Int(0), Int(0), Int(0), Int(0), Int(0) };
    auto polymod = Polymod(chia::utils::ConnectContainers(values, zeros)) ^ M;
    std::vector<Int> checksum;
    for (int i = 0; i < 6; ++i) {
        Int e = (polymod >> 5 * (5 - i)) & Int(31);
        checksum.push_back(e);
    }
    return checksum;
}

std::string Encode(std::string hrp, std::vector<Int> const& data)
{
    auto combined = chia::utils::ConnectContainers(data, CreateChecksum(hrp, data));
    std::stringstream ss;
    ss << hrp << "1";
    for (auto d : combined) {
        ss << CHARSET[d.ToInt()];
    }
    return ss.str();
}

std::string Strip(std::string_view str, char strip_ch)
{
    auto a = str.find_first_not_of(strip_ch);
    auto first = (a == std::string::npos) ? std::cbegin(str) : std::cbegin(str) + a;
    auto b = str.find_last_not_of(strip_ch);
    auto last = (b == std::string::npos) ? std::cend(str) : std::cbegin(str) + b + 1;
    return std::string(first, last);
}

std::vector<Int> ConvertBits(std::vector<Int> const& data, int frombits, int tobits, bool pad)
{
    Int acc { 0 }, bits { 0 };
    std::vector<Int> ret;
    Int maxv = (Int(1) << tobits) - Int(1);
    Int max_acc = (Int(1) << (frombits + tobits - 1)) - Int(1);
    for (Int value : data) {
        if (value < Int(0) || (value >> frombits) != Int(0)) {
            throw std::runtime_error("Invalid Value");
        }
        acc = ((acc << frombits) | value) & max_acc;
        bits += Int(frombits);
        while (bits >= Int(tobits)) {
            bits -= Int(tobits);
            ret.push_back((acc >> bits.ToInt()) & maxv);
        }
    }
    if (pad) {
        if (bits != Int(0)) {
            ret.push_back((acc << (Int(tobits) - bits).ToInt()) & maxv);
        } else if (bits >= Int(frombits) || ((acc << (Int(tobits) - bits).ToInt()) & maxv) != Int(0)) {
            throw std::runtime_error("Invalid bits");
        }
    }
    return ret;
}

} // namespace bech32
} // namespace chia
