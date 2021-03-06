#ifndef CHIA_MNEMONIC_H
#define CHIA_MNEMONIC_H

#include <array>
#include <string>
#include <vector>

#include "types.h"

namespace chia
{
namespace wallet
{

class Mnemonic
{
public:
    using Words = std::vector<std::string>;

    /// Generate a new mnemonic
    static Mnemonic GenerateNew(std::string lang = "en");

    /// Convert words into separated words string
    static std::string WordsToString(Mnemonic::Words const& words);

    /// Parse words from a string
    static Mnemonic::Words StringToWords(std::string str);

    /// Create a mnemonic object by importing words
    explicit Mnemonic(Words words, std::string lang = "en");

    /// Create a new mnemonic object by importing words in string
    explicit Mnemonic(std::string words, std::string lang = "en");

    /// Convert mnemonic to string
    std::string ToString() const;

    /// Get words of the mnemonic, it'll return an empty vector if the mnemonic is
    /// empty
    Words GetWords() const;

    /// Get the seed, fill with zeros if the mnemonic is empty
    Bytes64 GetSeed(std::string passphrase = "") const;

    /// Return `true` if current mnemonic is empty
    bool IsEmpty() const;

private:
    Words words_;
    Bytes bytes_;
};

} // namespace wallet
} // namespace chia

#endif
