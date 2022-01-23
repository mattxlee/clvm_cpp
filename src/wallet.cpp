#include "wallet.h"

#include "bech32.h"
#include "program.h"
#include "utils.h"

namespace chia {
namespace wallet {

Wallet::Wallet(std::string_view passphrase)
    : mnemonic_(Mnemonic::GenerateNew()), passphrase_(passphrase) {}

Wallet::Wallet(Mnemonic mnemonic, std::string_view passphrase)
    : mnemonic_(std::move(mnemonic)), passphrase_(passphrase) {}

Wallet::Wallet(std::string_view words, std::string_view passphrase)
    : mnemonic_(words), passphrase_(passphrase) {}

Address Wallet::GetAddress(int index) const {
  return GetKey(index).GetAddress();
}

Key Wallet::GetKey(uint32_t index) const {
  Key key(mnemonic_, passphrase_);
  return key.DerivePath({12381, 8444, 2, index});
}

}  // namespace wallet
}  // namespace chia
