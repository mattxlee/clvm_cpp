#include "crypto_utils.h"

namespace chia
{
namespace crypto_utils
{

void _C(int ret)
{
    // TODO throw error when an error occurs from inside the calculation
}

SHA256::SHA256()
    : ctx_(EVP_MD_CTX_new())
{
    _C(EVP_DigestInit(ctx_, EVP_sha256()));
}

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
