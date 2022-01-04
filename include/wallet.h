#ifndef CHIA_WALLET_H
#define CHIA_WALLET_H

#include "types.h"

namespace chia {

namespace wallet {

class Mnemonic;

class Wallet {
 public:
  /// Create a new empty wallet object
  Wallet();

  /// Create a wallet object with importing a mnemonic
  explicit Wallet(Mnemonic const& mnemonic);

  /// Get address by index
  Address GetAddress(int index) const;

  /// Make a signature with address index
  Signature Sign(Bytes const& bytes, int address_index) const;
};

}  // namespace wallet

}  // namespace chia

#endif
