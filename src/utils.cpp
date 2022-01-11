#include "utils.h"

#include <sstream>

namespace chia {
namespace utils {

char const hex_chars[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

char Byte4bToHexChar(uint8_t hex) { return hex_chars[hex]; }

uint8_t HexCharToByte4b(char ch) {
  for (int i = 0; i < 16; ++i) {
    if (std::tolower(ch) == hex_chars[i]) {
      return i;
    }
  }
  // Not found, the character is invalid
  throw std::runtime_error("invalid character");
}

std::string ByteToHex(uint8_t byte) {
  std::string hex(2, '0');
  uint8_t hi = (byte & 0xf0) >> 4;
  uint8_t lo = byte & 0x0f;
  hex[0] = Byte4bToHexChar(hi);
  hex[1] = Byte4bToHexChar(lo);
  return hex;
}

uint8_t ByteFromHex(std::string_view hex, int* consumed) {
  if (hex.empty()) {
    if (consumed) {
      *consumed = 0;
    }
    return 0;
  }
  if (hex.size() == 1) {
    if (consumed) {
      *consumed = 1;
    }
    return HexCharToByte4b(hex[0]);
  }
  uint8_t byte = (static_cast<int>(HexCharToByte4b(hex[0])) << 4) +
                 HexCharToByte4b(hex[1]);
  if (consumed) {
    *consumed = 2;
  }
  return byte;
}

std::string BytesToHex(Bytes const& bytes, std::string_view prefix) {
  std::stringstream ss;
  ss << prefix;
  for (uint8_t byte : bytes) {
    ss << ByteToHex(byte);
  }
  return ss.str();
}

Bytes BytesFromHex(std::string_view hex) {
  Bytes res;
  int consumed;
  uint8_t byte = ByteFromHex(hex, &consumed);
  while (consumed > 0) {
    res.push_back(byte);
    hex = hex.substr(consumed);
    // Next byte
    byte = ByteFromHex(hex, &consumed);
  }
  return res;
}

std::string ArgsToStr(std::vector<Bytes> const& args) {
  if (args.empty()) {
    return "";
  }
  std::stringstream ss;
  ss << "(";
  auto i = std::begin(args);
  ss << BytesToHex(*i);
  ++i;
  while (i != std::end(args)) {
    ss << ", " << BytesToHex(*i);
    ++i;
  }
  ss << ")";
  return ss.str();
}

}  // namespace utils
}  // namespace chia
