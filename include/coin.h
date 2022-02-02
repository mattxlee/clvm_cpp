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

private:
  Bytes32 parent_coin_info_;
  Bytes32 puzzle_hash_;
  Cost amount_;
};

class CoinSpend
{
public:
  Coin coin;
  Program puzzle_reveal;
  Program solution;

  std::vector<Coin> Additions();

  int ReservedFee();
};

} // namespace chia

#endif
