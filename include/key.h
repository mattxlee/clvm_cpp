#ifndef CHIA_KEY_H
#define CHIA_KEY_H

#include <string>
#include <string_view>

#include "types.h"

namespace chia::wallet
{

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

    /// Create a new key will be generated from the seed
    explicit Key(Bytes const& seed);

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

    /// Derive key for wallet
    Key GetWalletKey(uint32_t index = 0) const;

    /// Derive key for farmer
    Key GetFarmerKey(uint32_t index = 0) const;

    /// Derive key for pool
    Key GetPoolKey(uint32_t index = 0) const;

    /// Derive key for local
    Key GetLocalKey(uint32_t index = 0) const;

    /// Derive key for backup
    Key GetBackupKey(uint32_t index = 0) const;

    /// Calculate the address from public key
    Address GetAddress(std::string_view prefix = "xch") const;

private:
    PrivateKey priv_key_;
};

} // namespace chia::wallet

#endif
