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

bip3x::Bip39Mnemonic::MnemonicResult WordsToMnemonicResult(
    Mnemonic::Words const& words, std::string_view lang) {
  std::string str = Mnemonic::WordsToString(words);
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

Mnemonic Mnemonic::GenerateNew(std::string_view lang) {
  bip3x::Bip39Mnemonic::MnemonicResult res =
      bip3x::Bip39Mnemonic::generate(lang.data());
  return Mnemonic(res.words, lang);
}

std::string Mnemonic::WordsToString(Mnemonic::Words const& words) {
  std::stringstream ss;
  for (std::string const& word : words) {
    ss << " " << word;
  }
  return ss.str().substr(1);
}

Mnemonic::Words Mnemonic::StringToWords(std::string_view str) {
  int i{0}, last{0};
  Mnemonic::Words res;
  while (i < str.size()) {
    if (str[i] == ' ') {
      if (i - last > 0) {
        res.push_back(std::string(str.substr(last, i - last)));
      }
      last = i + 1;
    }
    ++i;
  }
  if (i - last - 1 > 0) {
    res.push_back(str.substr(last, i - last).data());
  }
  return res;
}

Mnemonic::Mnemonic(Words words, std::string_view lang)
    : words_(std::move(words)) {
  bip3x::Bip39Mnemonic::MnemonicResult res =
      utils::WordsToMnemonicResult(words_, lang);
  bytes_ = utils::CopyMnemonicResultToBytes(res);
}

Mnemonic::Mnemonic(std::string_view words, std::string_view lang)
    : Mnemonic(StringToWords(words), lang) {}

std::string Mnemonic::ToString() const { return WordsToString(words_); }

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
  std::string mnemonic = utils::NormalizeString(WordsToString(words_));
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
