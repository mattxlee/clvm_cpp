#include "puzzle.h"

#include <cassert>

#include <map>

#include "crypto_utils.h"
#include "types.h"
#include "utils.h"

#include "key.h"
#include "condition_opcode.h"

namespace chia::puzzle
{

class PredefinedPrograms {
public:
    enum class Names {
        DEFAULT_HIDDEN_PUZZLE,
        SYNTHETIC_MOD,
        MOD,
        P2_CONDITIONS,
    };

    static PredefinedPrograms& GetInstance() {
        static PredefinedPrograms instance;
        return instance;
    }

    Program operator[](Names name) {
        return Program::ImportFromBytes(progs_[name]);
    }

private:
    PredefinedPrograms() {
        progs_[Names::DEFAULT_HIDDEN_PUZZLE] = utils::BytesFromHex("ff0980");
        progs_[Names::SYNTHETIC_MOD] = utils::BytesFromHex("ff1dff02ffff1effff0bff02ff05808080");
        progs_[Names::MOD] = utils::BytesFromHex("ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080");
        progs_[Names::P2_CONDITIONS] = utils::BytesFromHex("ff04ffff0101ff0280");
    }

    std::map<Names, Bytes> progs_;
};

wallet::Key KeyFromRawPrivateKey(Bytes const& bytes)
{
    if (bytes.size() < wallet::Key::PRIV_KEY_LEN) {
        throw std::runtime_error("not enough number of bytes for a private-key");
    }
    auto private_key = utils::bytes_cast<wallet::Key::PRIV_KEY_LEN>(bytes);
    return wallet::Key(private_key);
}

char const* SZ_GROUP_ORDER = "73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001";

Int GROUP_ORDER()
{
    return Int(utils::BytesFromHex(SZ_GROUP_ORDER));
}

Int calculate_synthetic_offset(PublicKey const& public_key, Bytes32 const& hidden_puzzle_hash)
{
    Bytes32 hash = crypto_utils::MakeSHA256(utils::bytes_cast<wallet::Key::PUB_KEY_LEN>(public_key), utils::HashToBytes(hidden_puzzle_hash));
    Int offset(utils::bytes_cast<utils::HASH256_LEN>(hash));
    offset %= GROUP_ORDER();
    return offset;
}

PublicKey calculate_synthetic_public_key(PublicKey const& public_key, Bytes32 const& hidden_puzzle_hash)
{
    Int offset = calculate_synthetic_offset(public_key, hidden_puzzle_hash);
    auto bytes = offset.ToBytes();
    wallet::Key synthetic_offset = KeyFromRawPrivateKey(bytes);
    wallet::PubKey pk1(public_key), pk2(synthetic_offset.GetPublicKey());
    return (pk1 + pk2).GetPublicKey();
}

wallet::Key calculate_synthetic_secret_key(wallet::Key const& key, Bytes32 const& hidden_puzzle_hash)
{
    PrivateKey private_key = key.GetPrivateKey();
    Int secret_exponent = Int(utils::bytes_cast<wallet::Key::PRIV_KEY_LEN>(private_key));
    PublicKey public_key = key.GetPublicKey();
    Int synthetic_offset = calculate_synthetic_offset(public_key, hidden_puzzle_hash);
    Int synthetic_secret_exponent = (secret_exponent + synthetic_offset) % GROUP_ORDER();
    auto bytes = synthetic_secret_exponent.ToBytes();
    wallet::Key synthetic_secret_key = KeyFromRawPrivateKey(bytes);
    return synthetic_secret_key;
}

Program puzzle_for_synthetic_public_key(PublicKey const& synthetic_public_key)
{
    return PredefinedPrograms::GetInstance()[PredefinedPrograms::Names::MOD].Curry(ToSExp(synthetic_public_key));
}

Program puzzle_for_public_key_and_hidden_puzzle_hash(PublicKey const& public_key, Bytes32 const& hidden_puzzle_hash)
{
    auto synthetic_public_key = calculate_synthetic_public_key(public_key, hidden_puzzle_hash);

    return puzzle_for_synthetic_public_key(synthetic_public_key);
}

Program puzzle_for_public_key_and_hidden_puzzle(PublicKey const& public_key, Program const& hidden_puzzle)
{
    return puzzle_for_public_key_and_hidden_puzzle_hash(public_key, hidden_puzzle.GetTreeHash());
}

Program puzzle_for_public_key(PublicKey const& public_key)
{
    return puzzle_for_public_key_and_hidden_puzzle_hash(
        public_key, PredefinedPrograms::GetInstance()[PredefinedPrograms::Names::DEFAULT_HIDDEN_PUZZLE].GetTreeHash());
}

Bytes32 public_key_to_puzzle_hash(PublicKey const& public_key)
{
    return puzzle_for_public_key(public_key).GetTreeHash();
}

CLVMObjectPtr puzzle_for_conditions(CLVMObjectPtr conditions)
{
    Cost cost;
    CLVMObjectPtr result;
    std::tie(cost, result) = PredefinedPrograms::GetInstance()[PredefinedPrograms::Names::P2_CONDITIONS].Run(ToSExpList(conditions));
    return result;
}

Program solution_for_delegated_puzzle(CLVMObjectPtr delegated_puzzle, CLVMObjectPtr solution)
{
    return Program(ToSExpList(Bytes(), delegated_puzzle, solution));
}

Program solution_for_conditions(CLVMObjectPtr conditions)
{
    CLVMObjectPtr delegated_puzzle = puzzle_for_conditions(conditions);
    return solution_for_delegated_puzzle(delegated_puzzle, ToSExp(0));
}

CLVMObjectPtr make_create_coin_condition(Bytes32 const& puzzle_hash, uint64_t amount, Bytes const& memo)
{
    if (memo.empty()) {
        return ToSExpList(Bytes{ ConditionOpcode::ToBytes(ConditionOpcode::CREATE_COIN) }, utils::HashToBytes(puzzle_hash), amount);
    } else {
        return ToSExpList(Bytes{ ConditionOpcode::ToBytes(ConditionOpcode::CREATE_COIN) }, utils::HashToBytes(puzzle_hash), amount, memo);
    }
}

CLVMObjectPtr make_reserve_fee_condition(uint64_t fee)
{
    return ToSExpList(Bytes{ ConditionOpcode::ToBytes(ConditionOpcode::RESERVE_FEE)}, fee);
}

CLVMObjectPtr make_assert_coin_announcement(Bytes32 const& announcement_hash)
{
    return ToSExpList(Bytes { ConditionOpcode::ToBytes(ConditionOpcode::ASSERT_COIN_ANNOUNCEMENT)}, utils::HashToBytes(announcement_hash));
}

CLVMObjectPtr make_assert_puzzle_announcement(Bytes32 const& announcement_hash)
{
    return ToSExpList(Bytes { ConditionOpcode::ToBytes(ConditionOpcode::ASSERT_PUZZLE_ANNOUNCEMENT)}, utils::HashToBytes(announcement_hash));
}

CLVMObjectPtr make_create_coin_announcement(Bytes const& message)
{
    return ToSExpList(Bytes { ConditionOpcode::ToBytes(ConditionOpcode::CREATE_COIN_ANNOUNCEMENT)}, message);
}

CLVMObjectPtr make_create_puzzle_announcement(Bytes const& message)
{
    return ToSExpList(Bytes { ConditionOpcode::ToBytes(ConditionOpcode::CREATE_PUZZLE_ANNOUNCEMENT)}, message);
}

} // namespace chia::puzzle
