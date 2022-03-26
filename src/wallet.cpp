#include "wallet.h"

#include "bech32.h"
#include "program.h"
#include "utils.h"

namespace chia
{
namespace wallet
{

Wallet::Wallet(std::string passphrase)
    : mnemonic_(Mnemonic::GenerateNew())
    , passphrase_(passphrase)
{
}

Wallet::Wallet(Mnemonic mnemonic, std::string passphrase)
    : mnemonic_(std::move(mnemonic))
    , passphrase_(passphrase)
{
}

Wallet::Wallet(std::string words, std::string passphrase)
    : mnemonic_(words)
    , passphrase_(passphrase)
{
}

Address Wallet::GetAddress(int index) const { return GetKey(index).GetAddress(); }

Key Wallet::GetKey(uint32_t index) const
{
    Key key(mnemonic_, passphrase_);
    return key.DerivePath({ 12381, 8444, 2, index });
}

Key Wallet::GetFarmerKey(uint32_t index) const
{
    Key key(mnemonic_, passphrase_);
    return key.DerivePath({ 12381, 8444, 0, index });
}

Key Wallet::GetPoolKey(uint32_t index) const
{
    Key key(mnemonic_, passphrase_);
    return key.DerivePath({ 12381, 8444, 1, index });
}

Key Wallet::GetLocalKey(uint32_t index) const
{
    Key key(mnemonic_, passphrase_);
    return key.DerivePath({ 12381, 8444, 3, index });
}

Key Wallet::GetBackupKey(uint32_t index) const
{
    Key key(mnemonic_, passphrase_);
    return key.DerivePath({ 12381, 8444, 4, index });
}

Key Wallet::GetMainKey() const { return Key(mnemonic_, passphrase_); }

} // namespace wallet
} // namespace chia
