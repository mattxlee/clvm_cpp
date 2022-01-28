#include "coin.h"

#include "crypto_utils.h"

namespace chia
{

Bytes32 Coin::HashCoinList(std::vector<Coin> coin_list)
{
  std::sort(std::begin(coin_list), std::end(coin_list),
      [](Coin const& lhs, Coin const& rhs) -> bool {
        return lhs.GetNameStr() >= rhs.GetNameStr();
      });

  Bytes buffer;
  for (Coin const& coin : coin_list) {
    buffer = utils::ConnectBuffers(buffer, coin.GetName());
  }
  return crypto_utils::MakeSHA256(buffer);
}

Bytes32 Coin::GetName() const { return GetHash(); }

std::string Coin::GetNameStr() const
{
  return utils::BytesToHex(utils::bytes_cast<32>(GetName()));
}

Bytes32 Coin::GetHash() const
{
  return crypto_utils::MakeSHA256(
      parent_coin_info_, puzzle_hash_, utils::IntToBEBytes(amount_));
}

} // namespace chia
