#ifndef CHIA_WALLET_H
#define CHIA_WALLET_H

#include <string_view>

#include "key.h"
#include "mnemonic.h"
#include "types.h"

namespace chia {
namespace wallet {

class Wallet {
 public:
  /// Create a new empty wallet object
  Wallet();

  /// Create a wallet object by importing a mnemonic
  explicit Wallet(Mnemonic mnemonic);

  /// Create a wallet object from a passphrase words
  explicit Wallet(std::string_view words);

  /// Get mnemonic object
  Mnemonic const& GetMnemonic() const { return mnemonic_; }

  /// Get address by index
  Address GetAddress(int index) const;

  /// Get `Key` object that is according the index
  Key GetKey(int index) const;

 private:
  Mnemonic mnemonic_;
};

}  // namespace wallet
}  // namespace chia

#endif
