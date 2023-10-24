#include "crypto_utils.h"

#include "utils.h"

#include <stdexcept>

namespace chia
{
namespace crypto_utils
{

#ifdef __APPLE__
#include <TargetConditionals.h>

#if defined(TARGET_IPHONE_SIMULATOR) || defined(TARGET_OS_IPHONE)
#define USE_COMMON_CRYPTO
#endif

#endif // __APPLE__

#ifdef USE_COMMON_CRYPTO
#include <CommonCrypto/CommonCrypto.h>

struct SHA256::Impl {
    void Add(Bytes const& buff)
    {
        m_buff = utils::ConnectBuffers(m_buff, buff);
    }

    void Finish(uint8_t* pout)
    {
        CC_SHA256(m_buff.data(), static_cast<CC_LONG>(m_buff.size()), pout);
    }

private:
    Bytes m_buff;
};

#else
#include <openssl/crypto.h>

void _C(int ret)
{
    if (ret == 0) {
        throw std::runtime_error("error occurs when calling EVP functions");
    }
}

struct SHA256::Impl {
    Impl()
    {
        _C(EVP_DigestInit(ctx_, EVP_sha256()));
    }

    void Add(Bytes const& buff)
    {
        _C(EVP_DigestUpdate(ctx_, bytes.data(), bytes.size()));
    }

    void Finish(uint8_t* pout)
    {
        uint32_t size{256/8};
        EVP_DigestFinal_ex(ctx_, pout, &size);
    }
private:
    EVP_MD_CTX* ctx_;
};

#endif


SHA256::SHA256()
    : m_pimpl(new Impl)
{
}

SHA256::~SHA256() {}

void SHA256::Add(Bytes const& bytes) { m_pimpl->Add(bytes); }

Bytes32 SHA256::Finish()
{
    Bytes32 res;
    m_pimpl->Finish(res.data());
    return res;
}

} // namespace crypto_utils
} // namespace chia
