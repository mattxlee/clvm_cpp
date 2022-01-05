#ifndef CHIA_KEY_H
#define CHIA_KEY_H

#include "types.h"

namespace chia {
namespace wallet {

class Key {
 public:
  static int const PRIV_KEY_LEN = 32;
  static int const PUB_KEY_LEN = 48;
  static int const SIG_LEN = 96;

  static bool VerifySig(PublicKey const& pub_key, Bytes const& msg,
                        Signature const& sig);

  /// Create an empty key object without key creation
  Key();

  /// Create a object by importing the private key
  explicit Key(PrivateKey priv_key);

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

 private:
  PrivateKey priv_key_;
};

}  // namespace wallet

}  // namespace chia

#endif
