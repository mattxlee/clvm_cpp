#ifndef CHIA_UTILS_H
#define CHIA_UTILS_H

#include <string>
#include <string_view>

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
  assert(rhs.size() >= LEN);

  std::array<uint8_t, LEN> res;
  memcpy(res.data(), rhs.data(), LEN);
  return res;
}

template <typename Container>
Container ConnectContainers(Container const& lhs, Container const& rhs) {
  Container res = lhs;
  std::copy(std::begin(rhs), std::end(rhs), std::back_inserter(res));
  return res;
}

/**
 * Convert 4-bit byte to hex character
 *
 * @param hex A 4-bit byte will be convert to hex character, for example, 10
 * will be convertd to 'a'
 *
 * @return The converted hex character will be returned
 */
char Byte4bToHexChar(uint8_t hex);

/**
 * Convert hex character to a byte
 *
 * @param The hex character
 *
 * @return A byte from 0-15 (aka. 0x0 - 0xf)
 */
uint8_t HexCharToByte4b(char ch);

/**
 * Convert a byte array into hex string with the specified hex
 *
 * @param bytes The byte array
 *
 * @return Hex string with prefix
 */
std::string BytesToHex(Bytes const& bytes);

/**
 * Convert a hex string into a byte array
 *
 * @param hex The hex string contains hex bytes
 *
 * @return The converted byte array
 */
Bytes BytesFromHex(std::string_view hex);

/**
 * Convert byte array list to the string represents the arguments to a chialisp
 * function call
 *
 * @param args The byte array list
 *
 * @return A string represents the arguments to chialisp
 */
std::string ArgsToStr(std::vector<Bytes> const& args);

/**
 * Load hex string from a file
 *
 * @param file_path The file path of the hex file
 *
 * @return Hex string
 */
std::string LoadHexFromFile(std::string_view file_path);

/**
 * Convert a byte to an byte vector which contains 1 byte
 *
 * @param b The byte will be converted
 *
 * @return Bytes
 */
Bytes ByteToBytes(uint8_t b);

class BufferConnector {
 public:
  void Append(Bytes const& rhs);

  Bytes const& GetResult() const;

 private:
  Bytes result_;
};

template <typename... T>
Bytes ConnectBuffers(T&&... bufs) {
  BufferConnector conn;
  (conn.Append(std::forward<T>(bufs)), ...);
  return conn.GetResult();
}

template <typename T>
T IntFromBytesBE(Bytes const& bytes) {
  Bytes be;
  std::copy(std::rbegin(bytes), std::rend(bytes), std::back_inserter(be));
  int padding_bytes{0};
  if (bytes.size() < sizeof(T)) {
    padding_bytes = sizeof(T) - bytes.size();
  }
  for (int i = 0; i < padding_bytes; ++i) {
    be.push_back(0);
  }
  T res;
  memcpy(&res, be.data(), sizeof(T));
  return res;
}

template <typename... T>
Bytes SerializeBytes(T&&... vals) {
  Bytes res;
  (res.push_back(std::forward<T>(vals)), ...);
  return res;
}

}  // namespace utils
}  // namespace chia

#endif
