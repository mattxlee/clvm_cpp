#include "wallet.h"

#include <random.h>
#include <toolbox.h>

#include "bech32.h"
#include "program.h"
#include "utils.h"

namespace chia
{
namespace wallet
{

Key Wallet::GetKey(Key const& master_sk, uint32_t index) { return master_sk.DerivePath({ 12381, 8444, 2, index }); }

Key Wallet::GetFarmerKey(Key const& master_sk, uint32_t index)
{
    return master_sk.DerivePath({ 12381, 8444, 0, index });
}

Key Wallet::GetPoolKey(Key const& master_sk, uint32_t index) { return master_sk.DerivePath({ 12381, 8444, 1, index }); }

Key Wallet::GetLocalKey(Key const& master_sk, uint32_t index)
{
    return master_sk.DerivePath({ 12381, 8444, 3, index });
}

Key Wallet::GetBackupKey(Key const& master_sk, uint32_t index)
{
    return master_sk.DerivePath({ 12381, 8444, 4, index });
}

Wallet::Wallet(std::string passphrase)
    : mnemonic_(bip39::Mnemonic(bip39::RandomBytes(32).Random(), "english"))
    , passphrase_(passphrase)
{
}

Wallet::Wallet(bip39::Mnemonic mnemonic, std::string passphrase)
    : mnemonic_(std::move(mnemonic))
    , passphrase_(passphrase)
{
}

Wallet::Wallet(std::string words, std::string passphrase)
    : mnemonic_(bip39::ParseWords(words), "english")
    , passphrase_(passphrase)
{
}

Address Wallet::GetAddress(int index) const { return GetKey(index).GetAddress(); }

Key Wallet::GetKey(uint32_t index) const
{
    Key key(mnemonic_, passphrase_);
    return GetKey(key, index);
}

Key Wallet::GetFarmerKey(uint32_t index) const
{
    Key key(mnemonic_, passphrase_);
    return GetFarmerKey(key, index);
}

Key Wallet::GetPoolKey(uint32_t index) const
{
    Key key(mnemonic_, passphrase_);
    return GetPoolKey(key, index);
}

Key Wallet::GetLocalKey(uint32_t index) const
{
    Key key(mnemonic_, passphrase_);
    return GetLocalKey(key, index);
}

Key Wallet::GetBackupKey(uint32_t index) const
{
    Key key(mnemonic_, passphrase_);
    return GetBackupKey(key, index);
}

Key Wallet::GetMainKey() const { return Key(mnemonic_, passphrase_); }

} // namespace wallet
} // namespace chia
