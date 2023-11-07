#include "puzzle.h"

#include <cassert>

#include <map>

#include "types.h"
#include "utils.h"

#include "key.h"

namespace chia::puzzle
{

class PredefinedPrograms {
public:
    enum class Names {
        DEFAULT_HIDDEN_PUZZLE,
        SYNTHETIC_MOD,
        MOD,
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
    }

    std::map<Names, Bytes> progs_;
};

PublicKey calculate_synthetic_public_key(PublicKey const& public_key, Bytes32 const& hidden_puzzle_hash)
{
    assert(!public_key.empty());
    Cost cost;
    CLVMObjectPtr pk;
    std::tie(cost, pk) = PredefinedPrograms::GetInstance()[PredefinedPrograms::Names::SYNTHETIC_MOD].Run(ToSExpList(public_key, utils::HashToBytes(hidden_puzzle_hash)));
    return utils::bytes_cast<wallet::Key::PUB_KEY_LEN>(Atom(pk));
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

} // namespace chia::puzzle
