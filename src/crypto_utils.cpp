#include "crypto_utils.h"

#include <stdexcept>

namespace chia
{
namespace crypto_utils
{

void _C(int ret)
{
    if (ret == 0) {
        throw std::runtime_error("error occurs when calling EVP functions");
    }
}

SHA256::SHA256()
    : ctx_(EVP_MD_CTX_new())
{
    _C(EVP_DigestInit(ctx_, EVP_sha256()));
}

SHA256::~SHA256() { EVP_MD_CTX_destroy(ctx_); }

void SHA256::Add(Bytes const& bytes) { _C(EVP_DigestUpdate(ctx_, bytes.data(), bytes.size())); }

Bytes32 SHA256::Finish()
{
    Bytes32 res;
    unsigned int s = 32;
    EVP_DigestFinal_ex(ctx_, res.data(), &s);
    return res;
}

} // namespace crypto_utils
} // namespace chia
