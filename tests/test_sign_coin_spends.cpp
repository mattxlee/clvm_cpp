#include <gtest/gtest.h>

#include "condition_opcode.h"
#include "key.h"
#include "utils.h"

#include "coin.h"
#include "puzzle.h"

#define HIDDEN_PUZZLE_HASH (chia::puzzle::PredefinedPrograms::GetInstance()[chia::puzzle::PredefinedPrograms::Names::DEFAULT_HIDDEN_PUZZLE].GetTreeHash())
#define AGG_SIG_ME_ADDITIONAL_DATA (chia::utils::BytesFromHex("ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"))

class SignCoinSpendsTest : public testing::Test {
protected:
    void SetUp() override {
        sk1_h = top_sk().GetWalletKey(1);
        sk2_h = chia::wallet::Key(chia::puzzle::calculate_synthetic_secret_key(top_sk().GetWalletKey(2).GetPrivateKey(), HIDDEN_PUZZLE_HASH));
        sk1_u = top_sk().GetWalletKey(1, true);
        sk2_u = chia::wallet::Key(chia::puzzle::calculate_synthetic_secret_key(top_sk().GetWalletKey(2, true).GetPrivateKey(), HIDDEN_PUZZLE_HASH));

        pk1_h = sk1_h.GetPublicKey();
        pk2_h = sk2_h.GetPublicKey();
        pk1_u = sk1_u.GetPublicKey();
        pk2_u = sk2_u.GetPublicKey();

        additional_data = AGG_SIG_ME_ADDITIONAL_DATA;

        coin = chia::Coin(GenerateHash(), GenerateHash(), 0);
        puzzle = chia::Program(chia::ToSExp(1));
        solution_h = chia::Program(chia::ToSExpPair(chia::ToSExpList(chia::ConditionOpcode::ToBytes(chia::ConditionOpcode::AGG_SIG_UNSAFE), pk1_h, msg1), chia::ToSExpList(chia::ConditionOpcode::ToBytes(chia::ConditionOpcode::AGG_SIG_ME), pk2_h, msg2)));
        solution_u = chia::Program(chia::ToSExpPair(chia::ToSExpList(chia::ConditionOpcode::ToBytes(chia::ConditionOpcode::AGG_SIG_UNSAFE), pk1_u, msg1), chia::ToSExpList(chia::ConditionOpcode::ToBytes(chia::ConditionOpcode::AGG_SIG_ME), pk2_u, msg2)));

        spend_h = chia::CoinSpend(coin, puzzle.value(), solution_h.value());
        spend_u = chia::CoinSpend(coin, puzzle.value(), solution_u.value());
    }

    void TearDown() override {

    }

    void Test_SignCoinSpends()
    {

    }

    chia::wallet::Key top_sk()
    {
        chia::Bytes32 seed;
        seed.fill(1);
        chia::wallet::Key key(chia::utils::bytes_cast<32>(seed));
        return key;
    }

    chia::Bytes32 GenerateHash(uint8_t fill_by_char = '\0')
    {
        chia::Bytes32 result;
        result.fill(fill_by_char);
        return result;
    }

    chia::Bytes32 derive_ph(chia::PublicKey const& pk)
    {
        return GenerateHash();
    }

    chia::wallet::Key sk1_h;
    chia::wallet::Key sk2_h;
    chia::wallet::Key sk1_u;
    chia::wallet::Key sk2_u;

    chia::PublicKey pk1_h;
    chia::PublicKey pk2_h;
    chia::PublicKey pk1_u;
    chia::PublicKey pk2_u;

    char const* msg1 = "msg1";
    char const* msg2 = "msg2";

    chia::Bytes additional_data;

    chia::Coin coin;

    std::optional<chia::Program> puzzle;
    std::optional<chia::Program> solution_h;
    std::optional<chia::Program> solution_u;

    chia::CoinSpend spend_h;
    chia::CoinSpend spend_u;

public:
    std::optional<chia::PrivateKey> pk_to_sk(chia::PublicKey const& pk)
    {
        if (pk == pk1_h) {
            return sk1_h.GetPrivateKey();
        }
        return {};
    }

    std::optional<chia::PrivateKey> ph_to_sk(chia::Bytes32 const& ph)
    {
        if (ph == GenerateHash()) {
            return sk2_h.GetPrivateKey();
        }
        return {};
    }

};

TEST_F(SignCoinSpendsTest, TestCoinSpends)
{
    /*
        with pytest.raises(ValueError, match="no secret key"):
            await sign_coin_spends(
                [spend_h],
                pk_to_sk,
                lambda _: None,
                additional_data,
                1000000000,
                [derive_ph],
            )
    */
    EXPECT_THROW({
        chia::puzzle::sign_coin_spends({spend_h}, std::bind(&SignCoinSpendsTest::pk_to_sk, this, std::placeholders::_1), additional_data, 1000000000);
    }, std::runtime_error);
}
