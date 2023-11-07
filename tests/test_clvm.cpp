#include <fstream>
#include <string>

#include "gtest/gtest.h"

#include "assemble.h"
#include "int.h"
#include "key.h"
#include "operator_lookup.h"
#include "program.h"
#include "types.h"
#include "utils.h"
#include "bech32.h"
#include "puzzle.h"

TEST(Utilities, ByteToBytes)
{
    auto bytes = chia::utils::ByteToBytes('\1');
    EXPECT_EQ(bytes[0], '\1');
}

TEST(Utilities, Bytes)
{
    EXPECT_EQ(chia::utils::Byte4bToHexChar(10), 'a');
    EXPECT_EQ(chia::utils::HexCharToByte4b('b'), 11);

    chia::Bytes bytes(2);
    bytes[0] = 0xab;
    bytes[1] = 0xef;
    EXPECT_EQ(chia::utils::BytesToHex(bytes), "abef");
    EXPECT_EQ(chia::utils::BytesFromHex("abef"), bytes);

    chia::Bytes empty;
    EXPECT_TRUE(chia::utils::ConnectBuffers(empty, empty).empty());

    EXPECT_EQ(chia::utils::ConnectBuffers(bytes, bytes), chia::utils::BytesFromHex("abefabef"));

    EXPECT_EQ(chia::utils::ConnectBuffers(empty, bytes), chia::utils::BytesFromHex("abef"));

    EXPECT_EQ(chia::utils::ConnectBuffers(bytes, empty), chia::utils::BytesFromHex("abef"));
}

TEST(Utilities, IntBigEndianConvertion)
{
    EXPECT_EQ(chia::Int(chia::utils::SerializeBytes(0x01, 0x02)).ToInt(), 0x0102);
}

TEST(Utilities, Strip)
{
    char const* SZ_SOURCE = "  abcdefghijklmnopq      ";
    EXPECT_EQ(chia::bech32::Strip(SZ_SOURCE), "abcdefghijklmnopq");
    EXPECT_EQ(chia::bech32::Strip("abc"), "abc");
    EXPECT_EQ(chia::bech32::Strip(""), "");
}

std::string const s0 = "ff1dff02ffff1effff0bff02ff05808080";
std::string const s0_treehash = "624c5d5704d0decadfc0503e71bbffb6cdfe45025bce7cf3e6864d1eafe8f65e";

std::string const s1 = "ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080";
std::string const s1_treehash = "e9aaa49f45bad5c889b86ee3341550c155cfdd10c3a6757de618d20612fffd52";

TEST(CLVM_SHA256_treehash, LoadAndVerify_s0)
{
    auto prog = chia::Program::ImportFromHex(s0);
    auto treehash_bytes = chia::utils::BytesFromHex(s0_treehash);
    EXPECT_EQ(chia::utils::bytes_cast<32>(prog.GetTreeHash()), treehash_bytes);
}

TEST(CLVM_SHA256_treehash, LoadAndVerify_s1)
{
    auto prog = chia::Program::ImportFromHex(s1);
    auto treehash_bytes = chia::utils::BytesFromHex(s1_treehash);
    EXPECT_EQ(chia::utils::bytes_cast<32>(prog.GetTreeHash()), treehash_bytes);
}

TEST(CLVM_BigInt, Initial100)
{
    chia::Int i(100);
    EXPECT_EQ(i.ToInt(), 100);
}

TEST(CLVM_BigInt, InitialN100)
{
    chia::Int i(-100);
    EXPECT_EQ(i.ToInt(), -100);
}

TEST(CLVM_BigInt, Initial100FromBytes)
{
    chia::Int i(chia::utils::IntToBEBytes(100));
    EXPECT_EQ(i.ToInt(), 100);
}

TEST(CLVM_BigInt, Add)
{
    uint64_t a = 0x12345678;
    uint64_t b = 0x12345678;

    chia::Int aa(chia::utils::IntToBEBytes(a));
    chia::Int bb(chia::utils::IntToBEBytes(b));

    EXPECT_EQ((aa + bb).ToInt(), a + b);
}

TEST(CLVM_BigInt, Sub)
{
    uint64_t a = 0x12345678;
    uint64_t b = 0x12345678;

    chia::Int aa(chia::utils::IntToBEBytes(a));
    chia::Int bb(chia::utils::IntToBEBytes(b));

    EXPECT_EQ((aa - bb).ToInt(), a - b);
}

TEST(CLVM_SExp, List)
{
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

TEST(CLVM_MsbMask, MsbMask)
{
    EXPECT_EQ(chia::msb_mask(0x0), 0x0);
    EXPECT_EQ(chia::msb_mask(0x01), 0x01);
    EXPECT_EQ(chia::msb_mask(0x02), 0x02);
    EXPECT_EQ(chia::msb_mask(0x04), 0x04);
    EXPECT_EQ(chia::msb_mask(0x08), 0x08);
    EXPECT_EQ(chia::msb_mask(0x10), 0x10);
    EXPECT_EQ(chia::msb_mask(0x20), 0x20);
    EXPECT_EQ(chia::msb_mask(0x40), 0x40);
    EXPECT_EQ(chia::msb_mask(0x80), 0x80);
    EXPECT_EQ(chia::msb_mask(0x44), 0x40);
    EXPECT_EQ(chia::msb_mask(0x2a), 0x20);
    EXPECT_EQ(chia::msb_mask(0xff), 0x80);
    EXPECT_EQ(chia::msb_mask(0x0f), 0x08);
}

TEST(CLVM, OperatorLookup)
{
    chia::OperatorLookup ol;
    EXPECT_EQ(ol.KeywordToAtom("q"), 0x01);
    EXPECT_EQ(ol.KeywordToAtom("add"), 0x10);
}

int calculate_number(std::string s)
{
    auto f = chia::Assemble(s);
    chia::Program prog(f);
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run();
    EXPECT_EQ(r->GetNodeType(), chia::NodeType::Atom_Int);
    return chia::ToInt(r).ToInt();
}

bool calculate_bool(std::string s)
{
    auto f = chia::Assemble(s);
    chia::Program prog(f);
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run();
    return !chia::IsNull(r);
}

TEST(CLVM_RunProgram, Plus) { EXPECT_EQ(calculate_number("(+ (q . 2) (q . 5))"), 7); }

TEST(CLVM_RunProgram, Tuple)
{
    auto f = chia::Assemble("(q (2 . 3))");
    chia::Program prog(f);
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run();
    EXPECT_TRUE(chia::ListP(r));
    chia::ArgsIter i(r);
    EXPECT_TRUE(!i.IsEof());
    auto pair = i.NextCLVMObj();
    EXPECT_TRUE(chia::IsPair(pair));
    EXPECT_EQ(chia::Int(chia::ToInt(chia::First(pair))).ToInt(), 2);
    EXPECT_EQ(chia::Int(chia::ToInt(chia::Rest(pair))).ToInt(), 3);
}

TEST(CLVM_RunProgram, List)
{
    auto f = chia::Assemble("(q (1 2 3))");
    chia::Program prog(f);
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run();
    EXPECT_TRUE(chia::ListP(r));
    chia::ArgsIter i(r);
    auto list = i.NextCLVMObj();
    EXPECT_TRUE(chia::ListP(list));
    chia::ArgsIter i2(list);
    EXPECT_EQ(chia::Int(i2.Next()).ToInt(), 1);
    EXPECT_EQ(chia::Int(i2.Next()).ToInt(), 2);
    EXPECT_EQ(chia::Int(i2.Next()).ToInt(), 3);
}

TEST(CLVM_RunProgram, If)
{
    EXPECT_EQ(calculate_number("(i (= (q . 50) (q . 50)) (+ (q . 40) (q . 30)) (q . 20))"), 70);
}

TEST(CLVM_RunProgram, F) { EXPECT_EQ(calculate_number("(f (q . (80 90 100)))"), 80); }

TEST(CLVM_RunProgram, C)
{
    auto f = chia::Assemble("(c (q . 70) (q . (80 90 100)))");
    chia::Program prog(f);
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run();
    EXPECT_TRUE(chia::ListP(r));
    chia::ArgsIter i(r);
    EXPECT_EQ(i.NextInt().ToInt(), 70);
    EXPECT_EQ(i.NextInt().ToInt(), 80);
    EXPECT_EQ(i.NextInt().ToInt(), 90);
    EXPECT_EQ(i.NextInt().ToInt(), 100);
}

TEST(CLVM_RunProgram, R)
{
    auto f = chia::Assemble("(r (q . (80 90 100)))");
    chia::Program prog(f);
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run();
    EXPECT_TRUE(chia::ListP(r));
    chia::ArgsIter i(r);
    EXPECT_EQ(i.NextInt().ToInt(), 90);
    EXPECT_EQ(i.NextInt().ToInt(), 100);
}

TEST(CLVM_RunProgram, Complex) { EXPECT_EQ(calculate_number("(f (r (r (q . (100 110 120 130 140)))))"), 120); }

TEST(CLVM_RunProgram, Math)
{
    EXPECT_EQ(calculate_number("(- (q . 6) (q . 5))"), 1);
    EXPECT_EQ(calculate_number("(+ (q . 10) (q . 20) (q . 30) (q . 40))"), 100);
    EXPECT_EQ(calculate_number("(/ (q . 3) (q . -2))"), -2);
    EXPECT_EQ(calculate_number("(/ (q . -3) (q . 2))"), -2);
    EXPECT_EQ(calculate_number("(- (q . 5) (q . 7))"), -2);
    EXPECT_EQ(calculate_number("(+ (q . 3) (q . -8))"), -5);
    EXPECT_EQ(calculate_number("(+ (q . 0x000a) (q . 0x000b))"), 21);
}

TEST(CLVM_RunProgram, Bool)
{
    EXPECT_TRUE(calculate_bool("(= (q . 5) (q . 5))"));
    EXPECT_FALSE(calculate_bool("(= (q . 5) (q . 6))"));
    EXPECT_TRUE(calculate_bool("(= (q . 0) ())"));
    EXPECT_EQ(calculate_number("(+ (q . 70) ())"), 70);
}

TEST(CLVM_RunProgram, FlowControl)
{
    EXPECT_EQ(calculate_number("(i (q . 0) (q . 70) (q . 80))"), 80);
    EXPECT_EQ(calculate_number("(i (q . 1) (q . 70) (q . 80))"), 70);
    EXPECT_EQ(calculate_number("(i (q . 12) (q . 70) (q . 80))"), 70);
    EXPECT_EQ(calculate_number("(i () (q . 70) (q . 80))"), 80);
}

TEST(CLVM_RunProgram, Environment)
{
    auto f = chia::Assemble("1");
    chia::Program prog(f);
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run(chia::Assemble("(\"this\" \"is the\" \"environement\")"));
    EXPECT_TRUE(chia::ListP(r));
    chia::ArgsIter i(r);
    EXPECT_EQ(chia::ToString(i.NextCLVMObj()), "this");
    EXPECT_EQ(chia::ToString(i.NextCLVMObj()), "is the");
    EXPECT_EQ(chia::ToString(i.NextCLVMObj()), "environement");
}

TEST(CLVM_RunProgram, Env_Complex)
{
    auto f = chia::Assemble("(f (f (r 1)))");
    chia::Program prog(f);
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run(chia::Assemble("((70 80) (90 100) (110 120))"));
    EXPECT_EQ(r->GetNodeType(), chia::NodeType::Atom_Int);
    EXPECT_EQ(chia::ToInt(r).ToInt(), 90);
}

TEST(CLVM_RunProgram, Env_Complex2)
{
    auto f = chia::Assemble("(f (f (r 1)))");
    chia::Program prog(f);
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run(chia::Assemble("((70 80) ((91 92 93 94 95) 100) (110 120))"));
    EXPECT_TRUE(chia::ListP(r));
    chia::ArgsIter i(r);
    EXPECT_EQ(i.NextInt().ToInt(), 91);
    EXPECT_EQ(i.NextInt().ToInt(), 92);
    EXPECT_EQ(i.NextInt().ToInt(), 93);
    EXPECT_EQ(i.NextInt().ToInt(), 94);
    EXPECT_EQ(i.NextInt().ToInt(), 95);
}

TEST(CLVM_RunProgram, Env_Complex3)
{
    chia::Program prog(chia::Assemble("(+ (f 1) (q . 5))"));
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run(chia::Assemble("(10)"));
    EXPECT_EQ(chia::ToInt(r).ToInt(), 15);
}

TEST(CLVM_RunProgram, Env_Complex4)
{
    chia::Program prog(chia::Assemble("(* (f 1) (f 1))"));
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run(chia::Assemble("(10)"));
    EXPECT_EQ(chia::ToInt(r).ToInt(), 100);
}

TEST(CLVM_RunProgram, Env_ThroughInt1)
{
    chia::Program prog(chia::Assemble("1"));
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run(chia::Assemble("(\"example\" \"data\" \"for\" \"test\")"));
    chia::ArgsIter i(r);
    EXPECT_EQ(i.NextStr(), "example");
    EXPECT_EQ(i.NextStr(), "data");
    EXPECT_EQ(i.NextStr(), "for");
    EXPECT_EQ(i.NextStr(), "test");
}

TEST(CLVM_RunProgram, Env_ThroughInt2)
{
    chia::Program prog(chia::Assemble("2"));
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run(chia::Assemble("(\"example\" \"data\" \"for\" \"test\")"));
    EXPECT_EQ(chia::ToString(r), "example");
}

TEST(CLVM_RunProgram, Env_ThroughInt3)
{
    chia::Program prog(chia::Assemble("3"));
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run(chia::Assemble("(\"example\" \"data\" \"for\" \"test\")"));
    chia::ArgsIter i(r);
    EXPECT_EQ(i.NextStr(), "data");
    EXPECT_EQ(i.NextStr(), "for");
    EXPECT_EQ(i.NextStr(), "test");
}

TEST(CLVM_RunProgram, Env_ThroughInt5)
{
    chia::Program prog(chia::Assemble("5"));
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run(chia::Assemble("(\"example\" \"data\" \"for\" \"test\")"));
    EXPECT_EQ(chia::ToString(r), "data");
}

TEST(CLVM_RunProgram, Env_ThroughInt_Complex4)
{
    chia::Program prog(chia::Assemble("4"));
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run(chia::Assemble("((\"deeper\" \"example\") \"data\" \"for\" \"test\")"));
    EXPECT_EQ(chia::ToString(r), "deeper");
}

TEST(CLVM_RunProgram, Env_ThroughInt_Complex5)
{
    chia::Program prog(chia::Assemble("5"));
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run(chia::Assemble("((\"deeper\" \"example\") \"data\" \"for\" \"test\")"));
    EXPECT_EQ(chia::ToString(r), "data");
}

TEST(CLVM_RunProgram, Env_ThroughInt_Complex6)
{
    chia::Program prog(chia::Assemble("6"));
    chia::CLVMObjectPtr r;
    std::tie(std::ignore, r) = prog.Run(chia::Assemble("((\"deeper\" \"example\") \"data\" \"for\" \"test\")"));
    chia::ArgsIter i(r);
    EXPECT_EQ(i.NextStr(), "example");
}

TEST(CLVM_Address, ConvertPuzzleHash)
{
    char const* SZ_PUBLIC_KEY = "aea444ca6508d64855735a89491679daec4303e104d62b83d0e4d4c5280edd2b2480740031f68b374e4cd5d4aa6544e7";
    char const* SZ_ADDRESS = "xch19m2x9cdfeydgl4ua5ur48tvsd32mw779etfcyxjn0qwqnem22nwshhqjw5";
    auto pk = chia::utils::bytes_cast<chia::wallet::Key::PUB_KEY_LEN>(chia::utils::BytesFromHex(SZ_PUBLIC_KEY));
    auto puzzle_hash = chia::utils::BytesToInts(chia::utils::HashToBytes(chia::puzzle::public_key_to_puzzle_hash(pk)));
    std::string address = chia::bech32::EncodePuzzleHash(puzzle_hash, "xch");
    EXPECT_EQ(address, SZ_ADDRESS);
    auto decoded_puzzle_hash = chia::bech32::DecodePuzzleHash(address);
    EXPECT_EQ(decoded_puzzle_hash.size(), puzzle_hash.size());
    EXPECT_EQ(chia::utils::IntsToBytes(decoded_puzzle_hash), chia::utils::IntsToBytes(puzzle_hash));
}
