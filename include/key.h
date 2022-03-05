#ifndef CHIA_KEY_H
#define CHIA_KEY_H

#include <string_view>

#include "types.h"

namespace chia
{
namespace wallet
{

class Mnemonic;

class PubKey
{
public:
    PubKey();

    explicit PubKey(PublicKey pubkey);

    PubKey operator+(PubKey const& rhs) const;

    PubKey& operator+=(PubKey const& rhs);

    PublicKey const& GetPublicKey() const;

private:
    PublicKey pubkey_;
};

class Key
{
public:
    static int const PRIV_KEY_LEN = 32;
    static int const PUB_KEY_LEN = 48;
    static int const SIG_LEN = 96;

    static bool VerifySig(PublicKey const& pub_key, Bytes const& msg, Signature const& sig);

    static PublicKey CreatePublicKey();

    static PublicKey AddTwoPubkey(PublicKey const& lhs, PublicKey const& rhs);

    /// Create an empty key object without key creation
    Key();

    /// Create a object by importing the private key
    explicit Key(PrivateKey priv_key);

    /// Create a new key will be generated from the mnemonic
    Key(Mnemonic const& mnemonic, std::string_view passphrase);

    /// Return `true` when the key is empty
    bool IsEmpty() const;

    /// Generate a new private key
    void GenerateNew(Bytes const& seed);

    /// Get the private key value
    PrivateKey GetPrivateKey() const;

    /// Get public key
    PublicKey GetPublicKey() const;

    /// Make a signature
    Signature Sign(Bytes const& msg);

    /// Derive key
    Key DerivePath(std::vector<uint32_t> const& paths) const;

    /// Calculate the address from public key
    Address GetAddress() const;

private:
    PrivateKey priv_key_;
};

} // namespace wallet

} // namespace chia

#endif
