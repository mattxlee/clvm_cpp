#include "mnemonic.h"

#include <bip3x/Bip39Mnemonic.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslconf.h>
#include <openssl/sha.h>
#include <utf8proc.h>

#include <sstream>

namespace chia {
namespace wallet {

namespace utils {

Bytes CopyMnemonicResultToBytes(
    bip3x::Bip39Mnemonic::MnemonicResult const& res) {
  Bytes bytes(res.len);
  memcpy(bytes.data(), res.raw.data(), res.len);
  return bytes;
}

std::string WordsToString(Mnemonic::Words const& words) {
  std::stringstream ss;
  for (std::string const& word : words) {
    ss << " " << word;
  }
  return ss.str().substr(1);
}

bip3x::Bip39Mnemonic::MnemonicResult WordsToMnemonicResult(
    Mnemonic::Words const& words, std::string_view lang) {
  std::string str = utils::WordsToString(words);
  bip3x::bytes_data bytes =
      bip3x::Bip39Mnemonic::decodeMnemonic(str.data(), lang.data());
  return bip3x::Bip39Mnemonic::encodeBytes(bytes.data(), lang.data());
}

std::string NormalizeString(std::string_view str) {
  auto sz = reinterpret_cast<char const*>(
      utf8proc_NFKD(reinterpret_cast<uint8_t const*>(str.data())));
  return sz;
}

}  // namespace utils

Mnemonic::Mnemonic() {}

Mnemonic::Mnemonic(Words words) : words_(std::move(words)) {}

void Mnemonic::GenerateNew() {
  bip3x::Bip39Mnemonic::MnemonicResult res = bip3x::Bip39Mnemonic::generate();
  words_ = std::move(res.words);
  bytes_ = utils::CopyMnemonicResultToBytes(res);
}

void Mnemonic::Import(Words words, std::string_view lang) {
  words_ = std::move(words);
  bip3x::Bip39Mnemonic::MnemonicResult res =
      utils::WordsToMnemonicResult(words_, lang);
  bytes_ = utils::CopyMnemonicResultToBytes(res);
}

std::string Mnemonic::ToString() const { return utils::WordsToString(words_); }

Mnemonic::Words Mnemonic::GetWords() const { return words_; }

/**
 * Generating seed method is copied from chia-network:
 *
 * def mnemonic_to_seed(mnemonic: str, passphrase: str) -> bytes:
 *   """
 *   Uses BIP39 standard to derive a seed from entropy bytes.
 *   """
 *   salt_str: str = "mnemonic" + passphrase
 *   salt = unicodedata.normalize("NFKD", salt_str).encode("utf-8")
 *   mnemonic_normalized = unicodedata.normalize("NFKD",
 *       mnemonic).encode("utf-8")
 *   seed = pbkdf2_hmac("sha512", mnemonic_normalized, salt, 2048)

 *   assert len(seed) == 64
 *   return seed
 */
Bytes64 Mnemonic::GetSeed(std::string_view passphrase) const {
  std::string salt =
      utils::NormalizeString(std::string("mnemonic") + passphrase.data());
  std::string mnemonic = utils::NormalizeString(utils::WordsToString(words_));
  Bytes64 digest;
  int len =
      PKCS5_PBKDF2_HMAC(mnemonic.data(), mnemonic.size(),
                        reinterpret_cast<uint8_t const*>(salt.data()),
                        salt.size(), 2048, EVP_sha512(), 64, digest.data());
  assert(len == 64);
  return digest;
}

bool Mnemonic::IsEmpty() const { return words_.empty(); }

}  // namespace wallet
}  // namespace chia
