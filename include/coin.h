#ifndef CHIA_COIN_H
#define CHIA_COIN_H

#include <vector>
#include <set>
#include <map>

#include "sexp_prog.h"
#include "types.h"

namespace bls {
    class G1Element;
    class G2Element;
} // namespace bls

namespace chia
{

class Coin
{
public:
    static Bytes32 HashCoinList(std::vector<Coin> coin_list);

    Coin() = default;

    Coin(Bytes parent_coin_info, Bytes puzzle_hash, uint64_t amount);

    Coin(Bytes32 const& parent_coin_info, Bytes32 const& puzzle_hash, uint64_t amount);

    Bytes32 GetName() const;

    std::string GetNameStr() const;

    Cost GetAmount() const { return amount_; }

private:
    Bytes32 GetHash() const;

    Bytes parent_coin_info_;
    Bytes puzzle_hash_;
    Cost amount_;
};

struct Payment
{
    Bytes32 puzzle_hash;
    Cost amount;
    Bytes memo;
};

class CoinSpend
{
public:
    Coin coin;
    std::optional<Program> puzzle_reveal;
    std::optional<Program> solution;

    CoinSpend() = default;

    CoinSpend(CoinSpend const& rhs) = default;
    CoinSpend& operator=(CoinSpend const& rhs) = default;

    CoinSpend(Coin in_coin, Program in_puzzle_reveal, Program in_solution);

    std::vector<Coin> Additions() const;

    Cost ReservedFee();
};

class SpendBundle
{
public:
    static SpendBundle Aggregate(std::vector<SpendBundle> const& spend_bundles);

    SpendBundle(std::vector<CoinSpend> coin_spends, Signature sig);

    std::vector<CoinSpend> const& CoinSolutions() const { return coin_spends_; }

    std::vector<Coin> Additions() const;

    std::vector<Coin> Removals() const;

    uint64_t Fees() const;

    Bytes32 Name() const;

    std::vector<Coin> NotEphemeralAdditions() const;

    Signature const& GetAggregatedSignature() const { return aggregated_signature_; }

private:
    std::vector<CoinSpend> coin_spends_;
    Signature aggregated_signature_;
};

namespace puzzle {

using SecretKeyForPublicKeyFunc = std::function<std::optional<chia::PrivateKey>(chia::PublicKey const& public_key)>;
using SecretKeyForPuzzleHashFunc = std::function<std::optional<chia::PrivateKey>(chia::Bytes32 const& puzzle_hash)>;
using DeriveFunc = std::function<Bytes32(chia::PublicKey const& public_key)>;

SpendBundle sign_coin_spends(std::vector<CoinSpend> coin_spends, SecretKeyForPublicKeyFunc secret_key_for_public_key_f, SecretKeyForPuzzleHashFunc secret_key_for_puzzle_hash_f, Bytes const& additional_data = {}, Cost max_cost = 0, std::vector<DeriveFunc> const& derive_f_list = {});

Program make_solution(std::vector<Payment> const& primaries, std::set<Bytes> const& coin_announcements = {}, std::set<Bytes32> const& coin_announcements_to_assert = {}, std::set<Bytes> const& puzzle_announcements = {}, std::set<Bytes32> const& puzzle_announcements_to_assert = {}, CLVMObjectPtr additions = nullptr, uint64_t fee = 0);
} // namespace puzzle

} // namespace chia

#endif
