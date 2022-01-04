#ifndef CHIA_KEY_H
#define CHIA_KEY_H

#include "types.h"

namespace chia {
namespace wallet {

class Key {
 public:
  /// Create an empty key object without key creation
  Key();

  /// Create a new key object by importing a private key
  explicit Key(PrivateKey const& priv_key);

  /// Generate a new private key
  void GenerateNew();

  /// Get the private key value
  PrivateKey GetPrivateKey() const;

  /// Get public key
  PublicKey GetPublicKey() const;

  /// Make a signature
  Signature Sign(Bytes const& bytes);
};

}  // namespace wallet

}  // namespace chia

#endif
