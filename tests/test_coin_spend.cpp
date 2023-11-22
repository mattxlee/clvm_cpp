#include <iostream>

#include <gtest/gtest.h>

// #include "clvm/coin.h"
#include "clvm/bech32.h"
#include "clvm/utils.h"
#include "clvm/key.h"
#include "clvm/puzzle.h"

constexpr int AMOUNT = 1200;

TEST(CoinSpend, encode_and_decode)
{
    char const* SZ_ADDRESS = "txch15nysz640fnrwr0f03zv9gem3nrzev532kw8vcpr6lrlzx2s43x3s0n4u4e";
    char const* SZ_PUBLIC_KEY = "82077bcb6cfa4f1def38538284bf37a37f2f6fa44b3aca2d4885e97fd9eec58c53e851a3784057f0cf1a6de7ad03eb6e";

    chia::PublicKey public_key = chia::utils::bytes_cast<chia::wallet::Key::PUB_KEY_LEN>(chia::utils::BytesFromHex(SZ_PUBLIC_KEY));
    auto puzzle_hash = chia::utils::HashToBytes(chia::puzzle::puzzle_for_public_key(public_key).GetTreeHash());

    std::string address = chia::bech32::EncodePuzzleHash(chia::utils::BytesToInts(puzzle_hash), "txch");
    EXPECT_EQ(SZ_ADDRESS, address);

    // chia::Payment pay1;
    // pay1.puzzle_hash = chia::utils::BytesToHash(puzzle_hash);
    // pay1.amount = AMOUNT;
    // auto solution = chia::puzzle::make_solution({ pay1 });
    //
    // auto puzzle_reveal = chia::puzzle::puzzle_for_public_key(public_key);
    //
    // auto payments = chia::puzzle::decode_payments_from_solution(puzzle_reveal, solution);
    // EXPECT_EQ(payments.size(), 1);
}
