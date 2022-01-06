#include "wallet.h"

namespace chia {
namespace wallet {

Wallet::Wallet(std::string_view passphrase)
    : mnemonic_(Mnemonic::GenerateNew()), passphrase_(passphrase) {}

Wallet::Wallet(Mnemonic mnemonic, std::string_view passphrase)
    : mnemonic_(std::move(mnemonic)), passphrase_(passphrase) {}

Wallet::Wallet(std::string_view words, std::string_view passphrase)
    : mnemonic_(words), passphrase_(passphrase) {}

Address Wallet::GetAddress(int index) const {
  Key key = GetKey(index);
  PublicKey pub_key = key.GetPublicKey();
  // TODO Convert pub-key to address
}

Key Wallet::GetKey(uint32_t index) const {
  Key key(mnemonic_, passphrase_);
  return key.DerivePath({12381, 8444, 2, index});
}

}  // namespace wallet
}  // namespace chia
