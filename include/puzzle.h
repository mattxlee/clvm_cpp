#ifndef CHIA_PUZZLE_UTILS_H
#define CHIA_PUZZLE_UTILS_H

#include "types.h"

#include "sexp_prog.h"

namespace chia::puzzle {

PublicKey calculate_synthetic_public_key(PublicKey const& public_key, Bytes32 const& hidden_puzzle_hash);

Program puzzle_for_synthetic_public_key(PublicKey const& synthetic_public_key);

Program puzzle_for_public_key_and_hidden_puzzle_hash(PublicKey const& public_key, Bytes32 const& hidden_puzzle_hash);

Program puzzle_for_public_key_and_hidden_puzzle(PublicKey const& public_key, Program const& hidden_puzzle);

Program puzzle_for_public_key(PublicKey const& public_key);

Bytes32 public_key_to_puzzle_hash(PublicKey const& public_key);

Program solution_for_conditions(CLVMObjectPtr conditions);

CLVMObjectPtr puzzle_for_conditions(CLVMObjectPtr conditions);

Program solution_for_delegated_puzzle(CLVMObjectPtr delegated_puzzle, CLVMObjectPtr solution);

CLVMObjectPtr make_create_coin_condition(Bytes32 const& puzzle_hash, uint64_t amount, Bytes const& memo);

} // namespace chia::puzzle

#endif
