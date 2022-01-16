#include "clvm.h"

#include <fstream>
#include <sstream>

#include "crypto_utils.h"
#include "key.h"
#include "utils.h"

namespace chia {

uint64_t const MAX_RESULT_BYTES = 10240;

uint64_t const INFINITE_COST = 0x7FFFFFFFFFFFFFFF;

namespace clvm {

static std::string_view SYNTHETIC_MOD = "calculate_synthetic_public_key.clvm";
static std::string_view p2_delegated_puzzle_or_hidden_puzzle_sha256_treehash =
    "e9aaa49f45bad5c889b86ee3341550c155cfdd10c3a6757de618d20612fffd52";

Bytes Run(Bytes const& prog, std::vector<Bytes> const& args) {
  // uint32_t res_len{MAX_RESULT_BYTES};
  // Bytes res(res_len);
  // std::string args_str = utils::ArgsToStr(args);
  // run_chia_program(prog.data(), prog.size(),
  //                  reinterpret_cast<uint8_t const*>(args_str.data()),
  //                  args_str.size(), res.data(), &res_len, INFINITE_COST, 0);
  // res.resize(res_len);
  // return res;
  return Bytes();
}

Bytes LoadAndRun(std::string_view script_path, std::vector<Bytes> const& args) {
  std::ifstream in(script_path, std::ios::binary);
  std::string hex = utils::LoadHexFromFile(script_path);
  Bytes prog_bytes = utils::BytesFromHex(hex);
  return Run(prog_bytes, args);
}

PublicKey CalculateSyntheticPublicKey(PublicKey const& pk,
                                      Bytes32 const& hidden_puzzle_hash) {
  return utils::bytes_cast<wallet::Key::PUB_KEY_LEN>(LoadAndRun(
      SYNTHETIC_MOD, {utils::bytes_cast<wallet::Key::PUB_KEY_LEN>(pk),
                      utils::bytes_cast<32>(hidden_puzzle_hash)}));
}

Bytes32 PuzzleForSyntheticPublicKey(PublicKey const& synthetic_pk) {
  Bytes32 script_treehash = utils::bytes_cast<32>(utils::BytesFromHex(
      p2_delegated_puzzle_or_hidden_puzzle_sha256_treehash));
  return crypto_utils::MakeSHA256(
      utils::bytes_cast<32>(script_treehash),
      utils::bytes_cast<wallet::Key::PUB_KEY_LEN>(synthetic_pk));
}

Bytes32 PuzzleForPk(PublicKey const& pk, Bytes32 const& hidden_puzzle_hash) {
  PublicKey synthetic_pk = CalculateSyntheticPublicKey(pk, hidden_puzzle_hash);
  return PuzzleForSyntheticPublicKey(synthetic_pk);
}

}  // namespace clvm
}  // namespace chia
