#ifndef CHIA_MNEMONIC_H
#define CHIA_MNEMONIC_H

#include <array>
#include <vector>

#include <string>
#include <string_view>

#include "types.h"

namespace chia {

namespace wallet {

class Mnemonic {
 public:
  using Words = std::vector<std::string>;

  /// Create an empty mnemonic object
  Mnemonic();

  /// Create a mnemonic object with words
  explicit Mnemonic(Words words);

  /// Generate a new set of mnemonic words
  void GenerateNew();

  /// Import mnemonic passphrase words
  void Import(Words words, std::string_view lang = "en");

  /// Convert mnemonic to string
  std::string ToString() const;

  /// Get words of the mnemonic, it'll return an empty vector if the mnemonic is
  /// empty
  Words GetWords() const;

  /// Get the seed, fill with zeros if the mnemonic is empty
  Bytes64 GetSeed(std::string_view passphrase) const;

  /// Return `true` if current mnemonic is empty
  bool IsEmpty() const;

 private:
  Words words_;
  Bytes bytes_;
};

}  // namespace wallet
}  // namespace chia

#endif
