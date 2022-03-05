#ifndef CHIA_CRYPT_UTILS_H
#define CHIA_CRYPT_UTILS_H

#include <openssl/evp.h>

#include "types.h"
#include "utils.h"

namespace chia
{
namespace crypto_utils
{

class SHA256
{
public:
    SHA256();

    void Add(Bytes const& bytes);

    Bytes32 Finish();

private:
    EVP_MD_CTX* ctx_ { nullptr };
};

inline void WriteBytes(SHA256&) { }

template <typename T, typename... Ts> void WriteBytes(SHA256& sha, T&& bytes, Ts&&... others)
{
    sha.Add(std::forward<T>(bytes));
    WriteBytes(sha, std::forward<Ts>(others)...);
}

template <typename... T> Bytes32 MakeSHA256(T&&... args)
{
    SHA256 sha;
    WriteBytes(sha, std::forward<T>(args)...);
    return sha.Finish();
}

} // namespace crypto_utils
} // namespace chia

#endif
