#ifndef CHIA_COIN_H
#define CHIA_COIN_H

#include <vector>

#include "types.h"

namespace chia
{

class Coin
{
public:
  static Bytes32 HashCoinList(std::vector<Coin> coin_list);

  Bytes32 GetName() const;

  std::string GetNameStr() const;

  Bytes32 GetHash() const;

private:
  Bytes32 parent_coin_info_;
  Bytes32 puzzle_hash_;
  uint64_t amount_;
};

} // namespace chia

#endif
