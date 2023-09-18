#ifndef CHIA_WALLET_H
#define CHIA_WALLET_H

#include <string>

#include <mnemonic.h>

#include "key.h"
#include "types.h"

namespace chia
{
namespace wallet
{

class Wallet
{
public:
    static Key GetKey(Key const& master_sk, uint32_t index);

    static Key GetFarmerKey(Key const& master_sk, uint32_t index);

    static Key GetPoolKey(Key const& master_sk, uint32_t index);

    static Key GetLocalKey(Key const& master_sk, uint32_t index);

    static Key GetBackupKey(Key const& master_sk, uint32_t index);

    /// Create a new empty wallet object
    explicit Wallet(std::string passphrase);

    /// Create a wallet object by importing a mnemonic
    Wallet(bip39::Mnemonic mnemonic, std::string passphrase);

    /// Create a wallet object from a passphrase words
    Wallet(std::string words, std::string passphrase);

    /// Get mnemonic object
    bip39::Mnemonic const& GetMnemonic() const { return mnemonic_; }

    /// Get address by index
    Address GetAddress(int index) const;

    /// Get `Key` object that is according the index
    Key GetKey(uint32_t index) const;

    Key GetFarmerKey(uint32_t index) const;

    Key GetPoolKey(uint32_t index) const;

    Key GetLocalKey(uint32_t index) const;

    Key GetBackupKey(uint32_t index) const;

    /// Get main-key which is generated directly from mnemonic
    Key GetMainKey() const;

private:
    bip39::Mnemonic mnemonic_;
    std::string passphrase_;
};

} // namespace wallet
} // namespace chia

#endif
