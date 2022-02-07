#include "coin.h"

#include <algorithm>
#include <cassert>
#include <map>
#include <tuple>
#include <vector>

#include <schemes.hpp>

#include "costs.h"
#include "crypto_utils.h"
#include "wallet.h"

namespace chia
{

struct ConditionOpcode {
  // AGG_SIG is ascii "1"

  // the conditions below require bls12-381 signatures

  static uint8_t AGG_SIG_UNSAFE[1];
  static uint8_t AGG_SIG_ME[1];

  // the conditions below reserve coin amounts and have to be accounted for in
  // output totals

  static uint8_t CREATE_COIN[1];
  static uint8_t RESERVE_FEE[1];

  // the conditions below deal with announcements, for inter-coin communication

  static uint8_t CREATE_COIN_ANNOUNCEMENT[1];
  static uint8_t ASSERT_COIN_ANNOUNCEMENT[1];
  static uint8_t CREATE_PUZZLE_ANNOUNCEMENT[1];
  static uint8_t ASSERT_PUZZLE_ANNOUNCEMENT[1];

  // the conditions below let coins inquire about themselves

  static uint8_t ASSERT_MY_COIN_ID[1];
  static uint8_t ASSERT_MY_PARENT_ID[1];
  static uint8_t ASSERT_MY_PUZZLEHASH[1];
  static uint8_t ASSERT_MY_AMOUNT[1];

  // the conditions below ensure that we're "far enough" in the future

  // wall-clock time
  static uint8_t ASSERT_SECONDS_RELATIVE[1];
  static uint8_t ASSERT_SECONDS_ABSOLUTE[1];

  // block index
  static uint8_t ASSERT_HEIGHT_RELATIVE[1];
  static uint8_t ASSERT_HEIGHT_ABSOLUTE[1];

  Bytes value;

  explicit ConditionOpcode(Bytes value)
      : value(std::move(value))
  {
  }

  explicit ConditionOpcode(uint8_t vals[1])
  {
    value.resize(1);
    value[0] = vals[0];
  }

  bool operator<(ConditionOpcode const& rhs) const { return value < rhs.value; }
};

uint8_t ConditionOpcode::AGG_SIG_UNSAFE[1] = { 49 };
uint8_t ConditionOpcode::AGG_SIG_ME[1] = { 50 };

// the conditions below reserve coin amounts and have to be accounted for in
// output totals

uint8_t ConditionOpcode::CREATE_COIN[1] = { 51 };
uint8_t ConditionOpcode::RESERVE_FEE[1] = { 52 };

// the conditions below deal with announcements, for inter-coin communication

uint8_t ConditionOpcode::CREATE_COIN_ANNOUNCEMENT[1] = { 60 };
uint8_t ConditionOpcode::ASSERT_COIN_ANNOUNCEMENT[1] = { 61 };
uint8_t ConditionOpcode::CREATE_PUZZLE_ANNOUNCEMENT[1] = { 62 };
uint8_t ConditionOpcode::ASSERT_PUZZLE_ANNOUNCEMENT[1] = { 63 };

// the conditions below let coins inquire about themselves

uint8_t ConditionOpcode::ASSERT_MY_COIN_ID[1] = { 70 };
uint8_t ConditionOpcode::ASSERT_MY_PARENT_ID[1] = { 71 };
uint8_t ConditionOpcode::ASSERT_MY_PUZZLEHASH[1] = { 72 };
uint8_t ConditionOpcode::ASSERT_MY_AMOUNT[1] = { 73 };

// the conditions below ensure that we're "far enough" in the future

// wall-clock time
uint8_t ConditionOpcode::ASSERT_SECONDS_RELATIVE[1] = { 80 };
uint8_t ConditionOpcode::ASSERT_SECONDS_ABSOLUTE[1] = { 81 };

// block index
uint8_t ConditionOpcode::ASSERT_HEIGHT_RELATIVE[1] = { 82 };
uint8_t ConditionOpcode::ASSERT_HEIGHT_ABSOLUTE[1] = { 83 };

struct ConditionWithArgs {
  ConditionOpcode opcode;
  std::vector<Bytes> vars;

  template <typename BytesIter>
  explicit ConditionWithArgs(ConditionOpcode opcode, BytesIter& it)
      : opcode(opcode)
  {
    while (!it.IsEof()) {
      vars.push_back(it.Next());
    }
  }
};

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
    Program& puzzle_reveal, Program& solution, int max_cost)
{
  auto [cost, r] = puzzle_reveal.Run(solution.GetSExp());
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
    std::map<ConditionOpcode, std::vector<ConditionWithArgs>> const&
        conditions_dict,
    Bytes32 const& input_coin_name)
{
  std::vector<Coin> output_coins;
  auto i = conditions_dict.find(ConditionOpcode(ConditionOpcode::CREATE_COIN));
  if (i != std::end(conditions_dict)) {
    for (auto const& cvp : i->second) {
      Bytes32 puzzle_hash = utils::bytes_cast<32>(cvp.vars[0]);
      Bytes amount_bin = cvp.vars[1];
      uint64_t amount = utils::IntFromBEBytes<uint64_t>(amount_bin);
      output_coins.emplace_back(
          std::move(input_coin_name), std::move(puzzle_hash), amount);
    }
  }
  return output_coins;
}

std::tuple<std::map<ConditionOpcode, std::vector<ConditionWithArgs>>, Cost>
conditions_dict_for_solution(
    Program& puzzle_reveal, Program& solution, Cost max_cost)
{
  auto [results, cost]
      = conditions_for_solution(puzzle_reveal, solution, max_cost);
  return std::make_tuple(conditions_by_opcode(results), cost);
}

std::vector<Coin> additions_for_solution(
    Bytes32 coin_name, Program& puzzle_reveal, Program& solution, Cost max_cost)
{
  auto [dic, cost]
      = conditions_dict_for_solution(puzzle_reveal, solution, max_cost);
  return created_outputs_for_conditions_dict(dic, coin_name);
}

Cost fee_for_solution(Program& puzzle_reveal, Program& solution, Cost max_cost)
{
  auto [dic, cost]
      = conditions_dict_for_solution(puzzle_reveal, solution, max_cost);
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
    std::map<ConditionOpcode, std::vector<ConditionWithArgs>> const&
        conditions_dict,
    Bytes32 const& coin_name, Bytes const& additional_data)
{
  assert(!coin_name.empty());
  std::vector<std::tuple<Bytes48, Bytes>> ret;

  auto i
      = conditions_dict.find(ConditionOpcode(ConditionOpcode::AGG_SIG_UNSAFE));

  for (auto const& cwa : i->second) {
    assert(cwa.vars.size() == 2);
    assert(cwa.vars[0].size() == 48 && cwa.vars[1].size() <= 1024);
    assert(!cwa.vars[0].empty() && !cwa.vars[1].empty());
    ret.push_back(
        std::make_pair(utils::bytes_cast<48>(cwa.vars[0]), cwa.vars[1]));
  }

  auto j = conditions_dict.find(ConditionOpcode(ConditionOpcode::AGG_SIG_ME));
  for (auto const& cwa : j->second) {
    assert(cwa.vars.size() == 2);
    assert(cwa.vars[0].size() == 48 && cwa.vars[1].size() <= 1024);
    assert(!cwa.vars[0].empty() && !cwa.vars[1].empty());
    ret.push_back(std::make_pair(utils::bytes_cast<48>(cwa.vars[0]),
        utils::ConnectBuffers(
            cwa.vars[1], utils::bytes_cast<32>(coin_name), additional_data)));
  }

  return ret;
}

/*******************************************************************************
 *
 * class Coin
 *
 ******************************************************************************/

Bytes32 Coin::HashCoinList(std::vector<Coin> coin_list)
{
  std::sort(std::begin(coin_list), std::end(coin_list),
      [](Coin const& lhs, Coin const& rhs) -> bool {
        return lhs.GetNameStr() >= rhs.GetNameStr();
      });

  Bytes buffer;
  for (Coin const& coin : coin_list) {
    buffer
        = utils::ConnectBuffers(buffer, utils::bytes_cast<32>(coin.GetName()));
  }
  return crypto_utils::MakeSHA256(buffer);
}

Coin::Coin(Bytes32 parent_coin_info, Bytes32 puzzle_hash, uint64_t amount)
    : parent_coin_info_(std::move(parent_coin_info))
    , puzzle_hash_(std::move(puzzle_hash))
    , amount_(amount)
{
}

Bytes32 Coin::GetName() const { return GetHash(); }

std::string Coin::GetNameStr() const
{
  return utils::BytesToHex(utils::bytes_cast<32>(GetName()));
}

Bytes32 Coin::GetHash() const
{
  return crypto_utils::MakeSHA256(utils::bytes_cast<32>(parent_coin_info_),
      utils::bytes_cast<32>(puzzle_hash_), utils::IntToBEBytes(amount_));
}

/*******************************************************************************
 *
 * class CoinSpend
 *
 ******************************************************************************/

std::vector<Coin> CoinSpend::Additions() const
{
  return additions_for_solution(
      coin.GetName(), puzzle_reveal, solution, INFINITE_COST);
}

int CoinSpend::ReservedFee()
{
  return fee_for_solution(puzzle_reveal, solution, INFINITE_COST);
}

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

SpendBundle SpendBundle::Aggregate(
    std::vector<SpendBundle> const& spend_bundles)
{
  std::vector<CoinSpend> coin_spends;
  std::vector<bls::G2Element> sigs;
  for (auto const& bundle : spend_bundles) {
    std::copy(std::begin(bundle.CoinSolutions()),
        std::end(bundle.CoinSolutions()), std::back_inserter(coin_spends));
    sigs.push_back(bls::G2Element::FromByteVector(
        utils::bytes_cast<wallet::Key::SIG_LEN>(bundle.aggregated_signature_)));
  }
  bls::G2Element agg_sig = bls::AugSchemeMPL().Aggregate(sigs);
  Signature sig = utils::bytes_cast<wallet::Key::SIG_LEN>(agg_sig.Serialize());
  return SpendBundle(std::move(coin_spends), sig);
}

std::vector<Coin> SpendBundle::Additions() const
{
  std::vector<Coin> items;
  for (auto const& coin_spend : coin_spends_) {
    std::copy(std::begin(coin_spend.Additions()),
        std::end(coin_spend.Additions()), std::back_inserter(items));
  }
  return items;
}

std::vector<Coin> SpendBundle::Removals() const
{
  std::vector<Coin> res;
  res.reserve(coin_spends_.size());
  std::transform(std::begin(coin_spends_), std::end(coin_spends_),
      std::back_inserter(res),
      [](CoinSpend const& coin_spend) -> Coin { return coin_spend.coin; });
  return res;
}

template <typename Iter, typename Pred>
uint64_t sum(Iter begin, Iter end, Pred pred)
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
  uint64_t amount_in = sum(std::begin(removals), std::end(removals),
      [](Coin const& coin) -> uint64_t { return coin.GetAmount(); });
  std::vector<Coin> additions = Additions();
  uint64_t amount_out = sum(std::begin(additions), std::end(additions),
      [](Coin const& coin) -> uint64_t { return coin.GetAmount(); });
  return amount_in - amount_out;
}

Bytes32 SpendBundle::Name() const { return Bytes32(); }

std::vector<Coin> SpendBundle::NotEphemeralAdditions() const
{
  std::vector<Coin> res;
  return res;
}

} // namespace chia
