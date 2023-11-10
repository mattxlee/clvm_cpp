#include "coin.h"

#include <cassert>

#include <algorithm>
#include <cassert>
#include <functional>
#include <map>
#include <tuple>
#include <vector>

#include <schemes.hpp>

#include "costs.h"
#include "crypto_utils.h"
#include "utils.h"
#include "key.h"
#include "int.h"

#include "condition_opcode.h"
#include "puzzle.h"

namespace chia
{

/// utilities

namespace puzzle {

ConditionWithArgs parse_sexp_to_condition(CLVMObjectPtr sexp)
{
    if (ListLen(sexp) < 1) {
        throw std::runtime_error("invalid condition");
    }
    ArgsIter i(sexp);
    ConditionOpcode opcode(i.Next());
    return ConditionWithArgs(opcode, i);
}

std::vector<ConditionWithArgs> parse_sexp_to_conditions(CLVMObjectPtr sexp)
{
    std::vector<ConditionWithArgs> results;
    ArgsIter i(sexp);
    while (!i.IsEof()) {
        auto _ = i.NextCLVMObj();
        results.push_back(parse_sexp_to_condition(_));
    }
    return results;
}

std::tuple<std::vector<ConditionWithArgs>, uint64_t> conditions_for_solution(
    Program const& puzzle_reveal, Program const& solution, uint64_t max_cost)
{
    Cost cost;
    CLVMObjectPtr r;
    std::tie(cost, r) = puzzle_reveal.Run(solution.GetSExp());
    auto results = parse_sexp_to_conditions(r);
    return std::make_tuple(results, cost);
}

std::map<ConditionOpcode, std::vector<ConditionWithArgs>> conditions_by_opcode(
    std::vector<ConditionWithArgs>& conditions)
{
    std::map<ConditionOpcode, std::vector<ConditionWithArgs>> d;
    for (auto const& cvp : conditions) {
        auto i = d.find(cvp.opcode);
        if (i == std::end(d)) {
            std::vector<ConditionWithArgs> list { cvp };
            d.emplace(cvp.opcode, list);
            continue;
        }
        i->second.push_back(cvp);
    }
    return d;
}

std::vector<Coin> created_outputs_for_conditions_dict(
    std::map<ConditionOpcode, std::vector<ConditionWithArgs>> const& conditions_dict, Bytes32 const& input_coin_name)
{
    std::vector<Coin> output_coins;
    auto i = conditions_dict.find(ConditionOpcode(ConditionOpcode::CREATE_COIN));
    if (i != std::end(conditions_dict)) {
        for (auto const& cvp : i->second) {
            Bytes32 puzzle_hash = utils::BytesToHash(cvp.vars[0]);
            Bytes amount_bin = cvp.vars[1];
            uint64_t amount = utils::IntFromBEBytes<uint64_t>(amount_bin);
            output_coins.emplace_back(std::move(input_coin_name), std::move(puzzle_hash), amount);
        }
    }
    return output_coins;
}

std::tuple<std::map<ConditionOpcode, std::vector<ConditionWithArgs>>, Cost> conditions_dict_for_solution(
    Program const& puzzle_reveal, Program const& solution, Cost max_cost)
{
    std::vector<ConditionWithArgs> results;
    Cost cost;
    std::tie(results, cost) = conditions_for_solution(puzzle_reveal, solution, max_cost);
    return std::make_tuple(conditions_by_opcode(results), cost);
}

std::vector<Coin> additions_for_solution(Bytes32 coin_name, Program const& puzzle_reveal, Program const& solution, Cost max_cost)
{
    std::map<chia::ConditionOpcode, std::vector<chia::ConditionWithArgs>> dic;
    Cost cost;
    std::tie(dic, cost) = conditions_dict_for_solution(puzzle_reveal, solution, max_cost);
    return created_outputs_for_conditions_dict(dic, coin_name);
}

Cost fee_for_solution(Program const& puzzle_reveal, Program const& solution, Cost max_cost)
{
    std::map<chia::ConditionOpcode, std::vector<chia::ConditionWithArgs>> dic;
    Cost cost;
    std::tie(dic, cost) = conditions_dict_for_solution(puzzle_reveal, solution, max_cost);
    if (dic.empty()) {
        return 0;
    }
    Cost total { 0 };
    auto i = dic.find(ConditionOpcode(ConditionOpcode::RESERVE_FEE));
    if (i != std::end(dic)) {
        for (auto const& cvp : i->second) {
            auto amount_bin = cvp.vars[0];
            Cost amount = utils::IntFromBEBytes<Cost>(amount_bin);
            total += amount;
        }
    }
    return total;
}

std::vector<std::tuple<Bytes48, Bytes>> pkm_pairs_for_conditions_dict(
    std::map<ConditionOpcode, std::vector<ConditionWithArgs>> const& conditions_dict, Bytes32 const& coin_name,
    Bytes const& additional_data)
{
    assert(!coin_name.empty());
    std::vector<std::tuple<Bytes48, Bytes>> ret;

    auto i = conditions_dict.find(ConditionOpcode(ConditionOpcode::AGG_SIG_UNSAFE));

    for (auto const& cwa : i->second) {
        assert(cwa.vars.size() == 2);
        assert(cwa.vars[0].size() == 48 && cwa.vars[1].size() <= 1024);
        assert(!cwa.vars[0].empty() && !cwa.vars[1].empty());
        ret.push_back(std::make_pair(utils::bytes_cast<48>(cwa.vars[0]), cwa.vars[1]));
    }

    auto j = conditions_dict.find(ConditionOpcode(ConditionOpcode::AGG_SIG_ME));
    for (auto const& cwa : j->second) {
        assert(cwa.vars.size() == 2);
        assert(cwa.vars[0].size() == 48 && cwa.vars[1].size() <= 1024);
        assert(!cwa.vars[0].empty() && !cwa.vars[1].empty());
        ret.push_back(std::make_pair(utils::bytes_cast<48>(cwa.vars[0]),
            utils::ConnectBuffers(cwa.vars[1], utils::HashToBytes(coin_name), additional_data)));
    }

    return ret;
}

Program make_solution(std::vector<Payment> const& primaries, std::set<Bytes> const& coin_announcements, std::set<Bytes32> const& coin_announcements_to_assert, std::set<Bytes> const& puzzle_announcements, std::set<Bytes32> const& puzzle_announcements_to_assert, CLVMObjectPtr additions, uint64_t fee)
{
    ListBuilder result_builder;
    if (additions) {
        ArgsIter iter(additions);
        while (!iter.IsEof()) {
            result_builder.Add(iter.NextCLVMObj());
        }
    }
    if (!primaries.empty()) {
        for (auto const& primary : primaries) {
            result_builder.Add(puzzle::make_create_coin_condition(primary.puzzle_hash, primary.amount, primary.memo));
        }
    }
    if (fee > 0) {
        result_builder.Add(puzzle::make_reserve_fee_condition(fee));
    }
    if (!coin_announcements.empty()) {
        for (auto const& announcement : coin_announcements) {
            result_builder.Add(puzzle::make_create_coin_announcement(announcement));
        }
    }
    if (!coin_announcements_to_assert.empty()) {
        for (auto const& announcement_hash : coin_announcements_to_assert) {
            result_builder.Add(puzzle::make_assert_coin_announcement(announcement_hash));
        }
    }
    if (!puzzle_announcements.empty()) {
        for (auto const& puzzle_announcement : puzzle_announcements) {
            result_builder.Add(puzzle::make_create_puzzle_announcement(puzzle_announcement));
        }
    }
    if (!puzzle_announcements_to_assert.empty()) {
        for (auto const& puzzle_announcement : puzzle_announcements_to_assert) {
            result_builder.Add(puzzle::make_assert_puzzle_announcement(puzzle_announcement));
        }
    }
    return Program(result_builder.GetRoot());
}

SpendBundle sign_coin_spends(std::vector<CoinSpend> coin_spends, SecretKeyForPublicKeyFunc secret_key_for_public_key_f, Bytes const& additional_data, Cost max_cost)
{
    std::vector<chia::Signature> signatures;
    std::vector<chia::PublicKey> public_keys;
    std::vector<Bytes> messages;
    for (auto const& coin_spend : coin_spends) {
        // Get AGG_SIG conditions
        std::map<chia::ConditionOpcode, std::vector<chia::ConditionWithArgs>> conditions_dict;
        Cost cost;
        std::tie(conditions_dict, cost)
            = conditions_dict_for_solution(coin_spend.puzzle_reveal.value(), coin_spend.solution.value(), max_cost);
        if (conditions_dict.empty()) {
            throw std::runtime_error("Sign transaction failed");
        }
        // Create signature
        auto pkm_pairs = pkm_pairs_for_conditions_dict(conditions_dict, coin_spend.coin.GetName(), additional_data);
        for (auto const& p : pkm_pairs) {
            PublicKey public_key;
            Bytes message;
            std::tie(public_key, message) = p;
            public_keys.push_back(public_key);
            messages.push_back(message);
            auto secret_key_opt = secret_key_for_public_key_f(public_key);
            if (!secret_key_opt.has_value()) {
                throw std::runtime_error("no secret key for public-key");
            }
            auto private_key = secret_key_opt.value();
            chia::wallet::Key key(private_key);
            auto signature = key.Sign(message);
            assert(chia::wallet::Key::VerifySignature(public_key, message, signature));
            signatures.push_back(std::move(signature));
        }
    }

    // Aggregate signatures
    auto aggregated_signature = chia::wallet::Key::AggregateSignatures(signatures);
    chia::wallet::Key::AggregateVerifySignature(public_keys, messages, aggregated_signature);
    return SpendBundle(std::move(coin_spends), aggregated_signature);
}

} // namespace puzzle

/*******************************************************************************
 *
 * class Coin
 *
 ******************************************************************************/

Bytes32 Coin::HashCoinList(std::vector<Coin> coin_list)
{
    std::sort(std::begin(coin_list), std::end(coin_list),
        [](Coin const& lhs, Coin const& rhs) -> bool { return lhs.GetNameStr() >= rhs.GetNameStr(); });

    Bytes buffer;
    for (Coin const& coin : coin_list) {
        buffer = utils::ConnectBuffers(buffer, utils::HashToBytes(coin.GetName()));
    }
    return crypto_utils::MakeSHA256(buffer);
}

Coin::Coin(Bytes parent_coin_info, Bytes puzzle_hash, uint64_t amount)
    : parent_coin_info_(std::move(parent_coin_info))
    , puzzle_hash_(std::move(puzzle_hash))
    , amount_(amount)
{
}

Coin::Coin(Bytes32 const& parent_coin_info, Bytes32 const& puzzle_hash, uint64_t amount)
    : parent_coin_info_(utils::bytes_cast<utils::HASH256_LEN>(parent_coin_info))
    , puzzle_hash_(utils::bytes_cast<utils::HASH256_LEN>(puzzle_hash))
    , amount_(amount)
{

}

Bytes32 Coin::GetName() const { return GetHash(); }

std::string Coin::GetNameStr() const { return utils::BytesToHex(utils::HashToBytes(GetName())); }

Bytes32 Coin::GetHash() const
{
    Int amountInt(amount_);
    return crypto_utils::MakeSHA256(parent_coin_info_, puzzle_hash_, amountInt.ToBytes());
}

/*******************************************************************************
 *
 * class CoinSpend
 *
 ******************************************************************************/

CoinSpend::CoinSpend(Coin in_coin, Program in_puzzle_reveal, Program in_solution)
    : coin(std::move(in_coin))
    , puzzle_reveal(std::move(in_puzzle_reveal))
    , solution(std::move(in_solution))
{
}

std::vector<Coin> CoinSpend::Additions() const
{
    return puzzle::additions_for_solution(coin.GetName(), puzzle_reveal.value(), solution.value(), INFINITE_COST);
}

Cost CoinSpend::ReservedFee() { return puzzle::fee_for_solution(puzzle_reveal.value(), solution.value(), INFINITE_COST); }

/*******************************************************************************
 *
 * class SpendBundle
 *
 ******************************************************************************/

SpendBundle::SpendBundle(std::vector<CoinSpend> coin_spends, Signature sig)
    : coin_spends_(std::move(coin_spends))
    , aggregated_signature_(std::move(sig))
{
}

SpendBundle SpendBundle::Aggregate(std::vector<SpendBundle> const& spend_bundles)
{
    std::vector<CoinSpend> coin_spends;
    std::vector<bls::G2Element> sigs;
    for (auto const& bundle : spend_bundles) {
        std::copy(
            std::begin(bundle.CoinSolutions()), std::end(bundle.CoinSolutions()), std::back_inserter(coin_spends));
        sigs.push_back(
            bls::G2Element::FromByteVector(utils::bytes_cast<wallet::Key::SIG_LEN>(bundle.aggregated_signature_)));
    }
    bls::G2Element agg_sig = bls::AugSchemeMPL().Aggregate(sigs);
    Signature sig = utils::bytes_cast<wallet::Key::SIG_LEN>(agg_sig.Serialize());
    return SpendBundle(std::move(coin_spends), sig);
}

std::vector<Coin> SpendBundle::Additions() const
{
    std::vector<Coin> items;
    for (auto const& coin_spend : coin_spends_) {
        std::copy(std::begin(coin_spend.Additions()), std::end(coin_spend.Additions()), std::back_inserter(items));
    }
    return items;
}

std::vector<Coin> SpendBundle::Removals() const
{
    std::vector<Coin> res;
    res.reserve(coin_spends_.size());
    std::transform(std::begin(coin_spends_), std::end(coin_spends_), std::back_inserter(res),
        [](CoinSpend const& coin_spend) -> Coin { return coin_spend.coin; });
    return res;
}

template <typename Iter, typename Pred> uint64_t sum(Iter begin, Iter end, Pred pred)
{
    uint64_t r { 0 };
    while (begin != end) {
        r += pred(*begin);
        ++begin;
    }
    return r;
}

uint64_t SpendBundle::Fees() const
{
    std::vector<Coin> removals = Removals();
    uint64_t amount_in
        = sum(std::begin(removals), std::end(removals), [](Coin const& coin) -> uint64_t { return coin.GetAmount(); });
    std::vector<Coin> additions = Additions();
    uint64_t amount_out = sum(
        std::begin(additions), std::end(additions), [](Coin const& coin) -> uint64_t { return coin.GetAmount(); });
    return amount_in - amount_out;
}

Bytes32 SpendBundle::Name() const { return Bytes32(); }

std::vector<Coin> SpendBundle::NotEphemeralAdditions() const
{
    std::vector<Coin> res;
    return res;
}

} // namespace chia
