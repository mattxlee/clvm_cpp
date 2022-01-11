#ifndef CHIA_CLVM_H
#define CHIA_CLVM_H

#include "types.h"

namespace chia {
namespace clvm {

Bytes32 PuzzleForPk(PublicKey const& pk, Bytes32 const& hidden_puzzle_hash);

}  // namespace clvm
}  // namespace chia

#endif
