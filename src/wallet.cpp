#include "wallet.h"

#include "bech32.h"
#include "clvm.h"
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
  Key key = GetKey(index);
  PublicKey pub_key = key.GetPublicKey();
  Bytes32 puzzle_hash = clvm::PuzzleForPk(
      pub_key,
      Program::ImportFromBytes(utils::BytesFromHex(DEFAULT_HIDDEN_PUZZLE))
          .GetTreeHash());
  std::vector<int> puzzle_hash_ivec;
  std::copy(std::begin(puzzle_hash), std::end(puzzle_hash),
            std::back_inserter(puzzle_hash_ivec));
  return bech32::Encode("xch", bech32::ConvertBits(puzzle_hash_ivec, 8, 5));
}

Key Wallet::GetKey(uint32_t index) const {
  Key key(mnemonic_, passphrase_);
  return key.DerivePath({12381, 8444, 2, index});
}

}  // namespace wallet
}  // namespace chia
