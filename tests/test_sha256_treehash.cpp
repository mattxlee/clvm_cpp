#include <fstream>
#include <string_view>

#include "gtest/gtest.h"
#include "program.h"
#include "types.h"
#include "utils.h"

TEST(Utilities, ByteToBytes) {
  auto bytes = chia::utils::ByteToBytes('\1');
  EXPECT_EQ(bytes[0], '\1');
}

TEST(Utilities, Bytes) {
  EXPECT_EQ(chia::utils::Byte4bToHexChar(10), 'a');
  EXPECT_EQ(chia::utils::HexCharToByte4b('b'), 11);

  chia::Bytes bytes(2);
  bytes[0] = 0xab;
  bytes[1] = 0xef;
  EXPECT_EQ(chia::utils::BytesToHex(bytes), "abef");
  EXPECT_EQ(chia::utils::BytesFromHex("abef"), bytes);

  chia::Bytes empty;
  EXPECT_TRUE(chia::utils::ConnectBuffers(empty, empty).empty());

  EXPECT_EQ(chia::utils::ConnectBuffers(bytes, bytes),
            chia::utils::BytesFromHex("abefabef"));

  EXPECT_EQ(chia::utils::ConnectBuffers(empty, bytes),
            chia::utils::BytesFromHex("abef"));

  EXPECT_EQ(chia::utils::ConnectBuffers(bytes, empty),
            chia::utils::BytesFromHex("abef"));
}

TEST(Utilities, IntBigEndianConvertion) {
  EXPECT_EQ(chia::utils::IntFromBytesBE<uint32_t>(
                chia::utils::SerializeBytes(0x01, 0x02)),
            0x0102);
}

std::string_view const s0 = "../clvm/calculate_synthetic_public_key.clvm.hex";
std::string_view const s0_treehash =
    "../clvm/calculate_synthetic_public_key.clvm.hex.sha256tree";

std::string_view const s1 =
    "../clvm/p2_delegated_puzzle_or_hidden_puzzle.clvm.hex";
std::string_view const s1_treehash =
    "../clvm/p2_delegated_puzzle_or_hidden_puzzle.clvm.hex.sha256tree";

TEST(CLVM_SHA256_treehash, LoadAndVerify_s0) {
  auto prog = chia::Program::LoadFromFile(s0);
  auto treehash_bytes =
      chia::utils::BytesFromHex(chia::utils::LoadHexFromFile(s0_treehash));
  EXPECT_EQ(chia::utils::bytes_cast<32>(prog.GetTreeHash()), treehash_bytes);
}

TEST(CLVM_SHA256_treehash, LoadAndVerify_s1) {
  auto prog = chia::Program::LoadFromFile(s1);
  auto treehash_bytes =
      chia::utils::BytesFromHex(chia::utils::LoadHexFromFile(s1_treehash));
  EXPECT_EQ(chia::utils::bytes_cast<32>(prog.GetTreeHash()), treehash_bytes);
}
