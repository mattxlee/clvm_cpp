#ifndef CHIA_COIN_H
#define CHIA_COIN_H

#include <vector>

#include "program.h"
#include "types.h"

namespace chia
{

class Coin
{
public:
    static Bytes32 HashCoinList(std::vector<Coin> coin_list);

    Coin(Bytes32 parent_coin_info, Bytes32 puzzle_hash, uint64_t amount);

    Bytes32 GetName() const;

    std::string GetNameStr() const;

    Bytes32 GetHash() const;

    Cost GetAmount() const { return amount_; }

private:
    Bytes32 parent_coin_info_;
    Bytes32 puzzle_hash_;
    Cost amount_;
};

class CoinSpend
{
public:
    Coin coin;
    mutable Program puzzle_reveal;
    mutable Program solution;

    std::vector<Coin> Additions() const;

    int ReservedFee();
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

private:
    std::vector<CoinSpend> coin_spends_;
    Signature aggregated_signature_;
};

} // namespace chia

#endif
