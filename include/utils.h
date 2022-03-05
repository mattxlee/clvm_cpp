#ifndef CHIA_UTILS_H
#define CHIA_UTILS_H

#include <cassert>
#include <cstring>

#include <string>
#include <string_view>

#include "int.h"
#include "types.h"

namespace chia
{
namespace utils
{

template <int LEN> Bytes bytes_cast(std::array<uint8_t, LEN> const& rhs)
{
    Bytes bytes(LEN, '\0');
    memcpy(bytes.data(), rhs.data(), LEN);
    return bytes;
}

template <int LEN> std::array<uint8_t, LEN> bytes_cast(Bytes const& rhs)
{
    assert(rhs.size() >= LEN);

    std::array<uint8_t, LEN> res;
    memcpy(res.data(), rhs.data(), LEN);
    return res;
}

template <typename Container> Container ConnectContainers(Container const& lhs, Container const& rhs)
{
    Container res = lhs;
    std::copy(std::begin(rhs), std::end(rhs), std::back_inserter(res));
    return res;
}

Bytes StrToBytes(std::string_view str);

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

/**
 * Get part of a bytes
 *
 * @param bytes The source of those bytes
 * @param start From where the part is
 * @param count How many bytes you want to crypto_utils
 *
 * @return The bytes you want
 */
Bytes SubBytes(Bytes const& bytes, int start, int count = 0);

std::vector<Int> BytesToInts(Bytes const& bytes);

class BufferConnector
{
public:
    void Append(Bytes const& rhs);

    Bytes const& GetResult() const;

private:
    Bytes result_;
};

inline void AppendBuffer(BufferConnector& conn) { }

template <typename T, typename... Ts> void AppendBuffer(BufferConnector& conn, T&& buf, Ts&&... bufs)
{
    conn.Append(buf);
    AppendBuffer(conn, std::forward<Ts>(bufs)...);
}

template <typename... T> Bytes ConnectBuffers(T&&... bufs)
{
    BufferConnector conn;
    AppendBuffer(conn, std::forward<T>(bufs)...);
    return conn.GetResult();
}

inline void PushBack(Bytes&) { }

template <typename T, typename... Ts> void PushBack(Bytes& res, T&& val, Ts&&... vals)
{
    res.push_back(val);
    PushBack(res, std::forward<Ts>(vals)...);
}

template <typename... T> Bytes SerializeBytes(T&&... vals)
{
    Bytes res;
    PushBack(res, std::forward<T>(vals)...);
    return res;
}

Bytes RevertBytes(Bytes const& in);

template <typename T> Bytes IntToBEBytes(T const& val)
{
    Bytes b(sizeof(val));
    memcpy(b.data(), &val, sizeof(val));
    b = RevertBytes(b);
    return b;
}

template <typename T> T IntFromBEBytes(Bytes const& bytes)
{
    Bytes r = RevertBytes(bytes);
    int num_bytes_to_copy = std::max(sizeof(T), r.size());
    T result { 0 };
    memcpy(&result, r.data(), num_bytes_to_copy);
    return result;
}

std::string ToUpper(std::string_view str);

} // namespace utils
} // namespace chia

#endif
