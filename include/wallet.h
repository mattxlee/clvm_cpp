#ifndef CHIA_WALLET_H
#define CHIA_WALLET_H

#include <string>
#include <string_view>

#include "key.h"
#include "mnemonic.h"
#include "types.h"

namespace chia
{
namespace wallet
{

class Wallet
{
public:
    /// Create a new empty wallet object
    explicit Wallet(std::string_view passphrase);

    /// Create a wallet object by importing a mnemonic
    Wallet(Mnemonic mnemonic, std::string_view passphrase);

    /// Create a wallet object from a passphrase words
    Wallet(std::string_view words, std::string_view passphrase);

    /// Get mnemonic object
    Mnemonic const& GetMnemonic() const { return mnemonic_; }

    /// Get address by index
    Address GetAddress(int index) const;

    /// Get `Key` object that is according the index
    Key GetKey(uint32_t index) const;

    /// Get main-key which is generated directly from mnemonic
    Key GetMainKey() const;

private:
    Mnemonic mnemonic_;
    std::string passphrase_;
};

} // namespace wallet
} // namespace chia

#endif
