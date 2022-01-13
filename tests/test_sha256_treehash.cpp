#include <fstream>
#include <string_view>

#include "gtest/gtest.h"
#include "program.h"
#include "types.h"
#include "utils.h"

std::string_view const s1 =
    "../clvm/p2_delegated_puzzle_or_hidden_puzzle.clvm.hex";

std::string_view const s1_treehash =
    "../clvm/p2_delegated_puzzle_or_hidden_puzzle.clvm.hex.sha256tree";

chia::Bytes LoadCLVM(std::string_view file_path) {
  std::ifstream in(file_path, std::ios::binary);
  if (!in.is_open()) {
    throw std::runtime_error("cannot open file to read");
  }
  in.seekg(0, std::ios::end);
  auto p = in.tellg();
  in.seekg(0, std::ios::beg);
  chia::Bytes res(p);
  in.read(reinterpret_cast<char*>(res.data()), p);
  assert(in.gcount() == p);
  return res;
}

TEST(CLVM_SHA256_treehash, LoadAndVerify) {
  auto prog = chia::Program::LoadFromFile(s1);
  auto treehash_bytes =
      chia::utils::BytesFromHex(chia::utils::LoadHexFromFile(s1_treehash));
  EXPECT_EQ(chia::utils::bytes_cast<32>(prog.GetTreeHash()), treehash_bytes);
}
