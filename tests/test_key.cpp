#include <iostream>

#include <gtest/gtest.h>

#include "clvm/bech32.h"
#include "clvm/key.h"
#include "clvm/puzzle.h"
#include "clvm/utils.h"

char const* SZ_PUBLIC_KEY = "aea444ca6508d64855735a89491679daec4303e104d62b83d0e4d4c5280edd2b2480740031f68b374e4cd5d4aa6544e7";
char const* SZ_ADDRESS = "xch19m2x9cdfeydgl4ua5ur48tvsd32mw779etfcyxjn0qwqnem22nwshhqjw5";

chia::Bytes PUZZLE_HASH_BYTES = { 0x2e, 0xd4, 0x62, 0xe1, 0xa9, 0xc9, 0x1a, 0x8f, 0xd7, 0x9d, 0xa7, 0x7, 0x53, 0xad, 0x90, 0x6c, 0x55, 0xb7, 0x7b, 0xc5, 0xca, 0xd3, 0x82, 0x1a, 0x53, 0x78, 0x1c, 0x9, 0xe7, 0x6a, 0x54, 0xdd };

TEST(Key, EncodePuzzleHash)
{
    std::string address = chia::bech32::EncodePuzzleHash(chia::utils::BytesToInts(PUZZLE_HASH_BYTES), "xch");
    EXPECT_EQ(address, SZ_ADDRESS);
}

TEST(Key, DecodePuzzleHash)
{
    auto puzzle_hash_ints = chia::bech32::DecodePuzzleHash(SZ_ADDRESS);

    EXPECT_EQ(chia::utils::IntsToBytes(puzzle_hash_ints), PUZZLE_HASH_BYTES);
}

TEST(Key, PublicKeyToPuzzleHash)
{
    auto pk_data = chia::utils::bytes_cast<chia::wallet::Key::PUB_KEY_LEN>(chia::utils::BytesFromHex(SZ_PUBLIC_KEY));

    chia::PublicKey public_key(pk_data);
    auto puzzle_hash_bytes = chia::utils::HashToBytes(chia::puzzle::public_key_to_puzzle_hash(public_key));
    EXPECT_EQ(puzzle_hash_bytes, PUZZLE_HASH_BYTES);
}
