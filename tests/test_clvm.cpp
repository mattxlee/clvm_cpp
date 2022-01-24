#include <fstream>
#include <string_view>

#include "gtest/gtest.h"
#include "int.h"
#include "key.h"
#include "mnemonic.h"
#include "program.h"
#include "types.h"
#include "utils.h"
#include "wallet.h"

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
  EXPECT_EQ(chia::Int(chia::utils::SerializeBytes(0x01, 0x02)).ToInt(), 0x0102);
}

std::string_view const s0 = "../clvm/calculate_synthetic_public_key.clvm.hex";
std::string_view const s0_treehash =
    "../clvm/calculate_synthetic_public_key.clvm.hex.sha256tree";

std::string_view const s1 =
    "../clvm/p2_delegated_puzzle_or_hidden_puzzle.clvm.hex";
std::string_view const s1_treehash =
    "../clvm/p2_delegated_puzzle_or_hidden_puzzle.clvm.hex.sha256tree";

TEST(CLVM_SHA256_treehash, LoadAndVerify_s0) {
  auto prog = chia::Program::ImportFromCompiledFile(s0);
  auto treehash_bytes =
      chia::utils::BytesFromHex(chia::utils::LoadHexFromFile(s0_treehash));
  EXPECT_EQ(chia::utils::bytes_cast<32>(prog.GetTreeHash()), treehash_bytes);
}

TEST(CLVM_SHA256_treehash, LoadAndVerify_s1) {
  auto prog = chia::Program::ImportFromCompiledFile(s1);
  auto treehash_bytes =
      chia::utils::BytesFromHex(chia::utils::LoadHexFromFile(s1_treehash));
  EXPECT_EQ(chia::utils::bytes_cast<32>(prog.GetTreeHash()), treehash_bytes);
}

TEST(CLVM_BigInt, Initial100) {
  chia::Int i(100);
  EXPECT_EQ(i.ToInt(), 100);
}

TEST(CLVM_BigInt, InitialN100) {
  chia::Int i(-100);
  EXPECT_EQ(i.ToInt(), -100);
}

TEST(CLVM_BigInt, Initial100FromBytes) {
  chia::Int i(chia::utils::IntToBEBytes(100));
  EXPECT_EQ(i.ToInt(), 100);
}

TEST(CLVM_BigInt, Add) {
  long a = 0x1234567812345678;
  long b = 0x1234567812345678;

  chia::Int aa(chia::utils::IntToBEBytes(a));
  chia::Int bb(chia::utils::IntToBEBytes(b));

  EXPECT_EQ((aa + bb).ToInt(), a + b);
}

TEST(CLVM_BigInt, Sub) {
  long a = 0x1234567812345678;
  long b = 0x1234567812345600;

  chia::Int aa(chia::utils::IntToBEBytes(a));
  chia::Int bb(chia::utils::IntToBEBytes(b));

  EXPECT_EQ((aa - bb).ToInt(), a - b);
}

TEST(CLVM_SExp, List) {
  auto sexp_list = chia::ToSExpList(10, 20, 30, 40);
  EXPECT_EQ(chia::ListLen(sexp_list), 4);

  chia::ArgsIter i(sexp_list);
  auto val10 = chia::Int(i.Next());
  auto val20 = chia::Int(i.Next());
  auto val30 = chia::Int(i.Next());
  auto val40 = chia::Int(i.Next());

  EXPECT_TRUE(i.IsEof());

  EXPECT_EQ(val10.ToInt(), 10);
  EXPECT_EQ(val20.ToInt(), 20);
  EXPECT_EQ(val30.ToInt(), 30);
  EXPECT_EQ(val40.ToInt(), 40);
}

TEST(CLVM_MsbMask, MsbMask) {
  EXPECT_EQ(chia::MSBMask(0x0), 0x0);
  EXPECT_EQ(chia::MSBMask(0x01), 0x01);
  EXPECT_EQ(chia::MSBMask(0x02), 0x02);
  EXPECT_EQ(chia::MSBMask(0x04), 0x04);
  EXPECT_EQ(chia::MSBMask(0x08), 0x08);
  EXPECT_EQ(chia::MSBMask(0x10), 0x10);
  EXPECT_EQ(chia::MSBMask(0x20), 0x20);
  EXPECT_EQ(chia::MSBMask(0x40), 0x40);
  EXPECT_EQ(chia::MSBMask(0x80), 0x80);
  EXPECT_EQ(chia::MSBMask(0x44), 0x40);
  EXPECT_EQ(chia::MSBMask(0x2a), 0x20);
  EXPECT_EQ(chia::MSBMask(0xff), 0x80);
  EXPECT_EQ(chia::MSBMask(0x0f), 0x08);
}

TEST(CLVM_Mnemonic, WordsList) {
  auto words = chia::wallet::Mnemonic::StringToWords("hello world");
  EXPECT_EQ(words.size(), 2);
  EXPECT_EQ(words[0], "hello");
  EXPECT_EQ(words[1], "world");

  std::string str = chia::wallet::Mnemonic::WordsToString(words);
  EXPECT_EQ(str, "hello world");
}

/**
 * Private key 2450593623
 * Private key:
 * 5829ad7349855dbec352bb5564833938092afe642dee4eb4aa194c8878c23b20
 * Public key:
 * adce14eef36f77e00bdf2ce7c54d7e3687fcc2e90b6e6a6ec3163fe7ae4cb449fc840b6f6d0a7bf49abb94415900a920
 * Farmer public key:
 * 89cb70ca22bbb4e7c84b66f4c415ec5e17b4ed39e4ecd3b254818c15e407f7164fc81c0466006f3249c7f9e6b2b1d289
 * Pool public key:
 * 944d51fc3e7da74f85666bd7700e4cca1e8b033774e2c7db01f4bc0e7d14aaaeab05d4c40f740039d01a20f96fa7a1e1
 * Seed:
 return village first merit biology slim leaf assume link physical silk identify
 material peanut keen settle logic absorb better famous exit glove tower inhale

 * Address 0: xch19m2x9cdfeydgl4ua5ur48tvsd32mw779etfcyxjn0qwqnem22nwshhqjw5
 */

TEST(CLVM_Key, Verify) {
  chia::wallet::Mnemonic mnemonic(
      "return village first merit biology slim leaf assume link physical silk "
      "identify material peanut keen settle logic absorb better famous exit "
      "glove tower inhale");

  chia::wallet::Wallet wallet(mnemonic, "");
  chia::wallet::Key key = wallet.GetMainKey();

  auto pk = chia::utils::bytes_cast<chia::wallet::Key::PRIV_KEY_LEN>(
      key.GetPrivateKey());
  EXPECT_EQ(
      chia::utils::BytesFromHex(
          "5829ad7349855dbec352bb5564833938092afe642dee4eb4aa194c8878c23b20"),
      pk);

  auto pubk = chia::utils::bytes_cast<chia::wallet::Key::PUB_KEY_LEN>(
      key.GetPublicKey());
  EXPECT_EQ(chia::utils::BytesFromHex(
                "adce14eef36f77e00bdf2ce7c54d7e3687fcc2e90b6e6a6ec3163fe7ae4cb4"
                "49fc840b6f6d0a7bf49abb94415900a920"),
            pubk);
}
