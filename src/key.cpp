#include "key.h"

#include <filesystem>
#include <map>
#include <schemes.hpp>

#include "elements.hpp"
namespace fs = std::filesystem;

#include "bech32.h"
#include "mnemonic.h"
#include "program.h"
#include "utils.h"

namespace chia
{
namespace wallet
{

bool Key::VerifySig(
    PublicKey const& pub_key, Bytes const& msg, Signature const& sig)
{
  return bls::AugSchemeMPL().Verify(utils::bytes_cast<PUB_KEY_LEN>(pub_key),
      msg, utils::bytes_cast<SIG_LEN>(sig));
}

PubKey::PubKey()
{
  pubkey_ = utils::bytes_cast<Key::PUB_KEY_LEN>(bls::G1Element().Serialize());
}

PubKey::PubKey(PublicKey pubkey)
    : pubkey_(std::move(pubkey))
{
}

PubKey PubKey::operator+(PubKey const& rhs) const
{
  auto lhs_g1
      = bls::G1Element::FromBytes(bls::Bytes(pubkey_.data(), pubkey_.size()));
  auto rhs_g1 = bls::G1Element::FromBytes(
      bls::Bytes(rhs.pubkey_.data(), rhs.pubkey_.size()));
  auto res = bls::AugSchemeMPL().Aggregate({ lhs_g1, rhs_g1 });
  return PubKey(utils::bytes_cast<Key::PUB_KEY_LEN>(res.Serialize()));
}

PubKey& PubKey::operator+=(PubKey const& rhs)
{
  *this = *this + rhs;
  return *this;
}

PublicKey const& PubKey::GetPublicKey() const { return pubkey_; }

PublicKey Key::CreatePublicKey()
{
  return utils::bytes_cast<PUB_KEY_LEN>(bls::G1Element().Serialize());
}

PublicKey Key::AddTwoPubkey(PublicKey const& lhs, PublicKey const& rhs)
{
  bls::G1Element g1lhs
      = bls::G1Element::FromBytes(bls::Bytes(lhs.data(), lhs.size()));
  bls::G1Element g1rhs
      = bls::G1Element::FromBytes(bls::Bytes(rhs.data(), rhs.size()));
  auto res = g1lhs + g1rhs;
  return utils::bytes_cast<PUB_KEY_LEN>(res.Serialize());
}

Key::Key() { }

Key::Key(PrivateKey priv_key)
    : priv_key_(std::move(priv_key))
{
}

Key::Key(Mnemonic const& mnemonic, std::string_view passphrase)
{
  Bytes64 seed = mnemonic.GetSeed(passphrase);
  priv_key_ = utils::bytes_cast<PRIV_KEY_LEN>(
      bls::AugSchemeMPL().KeyGen(utils::bytes_cast<64>(seed)).Serialize());
}

bool Key::IsEmpty() const { return priv_key_.empty(); }

void Key::GenerateNew(Bytes const& seed)
{
  bls::PrivateKey bls_priv_key = bls::AugSchemeMPL().KeyGen(seed);
  Bytes priv_key_bytes = bls_priv_key.Serialize();
  priv_key_ = utils::bytes_cast<PRIV_KEY_LEN>(priv_key_bytes);
}

PrivateKey Key::GetPrivateKey() const { return priv_key_; }

PublicKey Key::GetPublicKey() const
{
  bls::PrivateKey bls_priv_key = bls::PrivateKey::FromBytes(
      bls::Bytes(utils::bytes_cast<PRIV_KEY_LEN>(priv_key_)));
  return utils::bytes_cast<PUB_KEY_LEN>(
      bls_priv_key.GetG1Element().Serialize());
}

Signature Key::Sign(Bytes const& msg)
{
  bls::PrivateKey bls_priv_key = bls::PrivateKey::FromBytes(
      bls::Bytes(utils::bytes_cast<PRIV_KEY_LEN>(priv_key_)));
  Bytes sig_bytes = bls::AugSchemeMPL().Sign(bls_priv_key, msg).Serialize();
  return utils::bytes_cast<SIG_LEN>(sig_bytes);
}

Key Key::DerivePath(std::vector<uint32_t> const& paths) const
{
  bls::PrivateKey bls_priv_key = bls::PrivateKey::FromBytes(
      bls::Bytes(utils::bytes_cast<PRIV_KEY_LEN>(priv_key_)));
  auto sk { bls_priv_key };
  for (uint32_t path : paths) {
    sk = bls::AugSchemeMPL().DeriveChildSk(sk, path);
  }
  return Key(utils::bytes_cast<PRIV_KEY_LEN>(sk.Serialize()));
}

namespace puzzle
{

std::string_view DEFAULT_HIDDEN_PUZZLE = "DEFAULT_HIDDEN_PUZZLE ";
std::string_view MOD = "MOD";
std::string_view SYNTHETIC_MOD = "SYNTHETIC_MOD";

class CLVMPrograms
{
public:
  static CLVMPrograms& GetInstance()
  {
    static CLVMPrograms instance;
    return instance;
  }

  void SetPrefix(std::string_view new_prefix) { prefix_ = new_prefix; }

  void SetEntry(std::string_view name, Bytes const& bytes)
  {
    Entry entry;
    entry.type = EntryType::Bytes;
    entry.content = utils::BytesToHex(bytes);
    progs_.insert_or_assign(name.data(), std::move(entry));
  }

  void SetEntry(std::string_view name, std::string_view file_path)
  {
    Entry entry;
    entry.type = EntryType::File;
    entry.content = file_path;
    progs_.insert_or_assign(name.data(), std::move(entry));
  }

  Program GetProgram(std::string_view name) const
  {
    auto i = progs_.find(name.data());
    if (i == std::end(progs_)) {
      throw std::runtime_error("the program doesn't exist");
    }
    Entry const& entry = i->second;
    if (entry.type == EntryType::Bytes) {
      return Program::ImportFromBytes(utils::BytesFromHex(entry.content));
    } else if (entry.type == EntryType::File) {
      fs::path file_path;
      if (!prefix_.empty()) {
        file_path = fs::path(prefix_) / entry.content;
      } else {
        file_path = entry.content;
      }
      return Program::ImportFromCompiledFile(file_path.string());
    }
    throw std::runtime_error("invalid entry type");
  }

private:
  CLVMPrograms()
  {
    SetEntry(DEFAULT_HIDDEN_PUZZLE, utils::BytesFromHex("ff0980"));
    SetEntry(MOD, "p2_delegated_puzzle_or_hidden_puzzle.clvm.hex");
    SetEntry(SYNTHETIC_MOD, "calculate_synthetic_public_key.clvm.hex");
  }

private:
  enum class EntryType { File, Bytes };
  struct Entry {
    EntryType type;
    std::string content;
  };
  std::string prefix_ { "../clvm" };
  std::map<std::string, Entry> progs_;
};

PublicKey calculate_synthetic_public_key(
    PublicKey const& public_key, Bytes32 const& hidden_puzzle_hash)
{
  assert(!public_key.empty());
  auto [cost, pk] = CLVMPrograms::GetInstance()
                        .GetProgram(SYNTHETIC_MOD)
                        .Run(ToSExpList(public_key,
                            utils::bytes_cast<32>(hidden_puzzle_hash)));
  return utils::bytes_cast<Key::PUB_KEY_LEN>(Atom(pk));
}

Program puzzle_for_synthetic_public_key(PublicKey const& synthetic_public_key)
{
  return CLVMPrograms::GetInstance().GetProgram(MOD).Curry(
      ToSExp(synthetic_public_key));
}

Program puzzle_for_public_key_and_hidden_puzzle_hash(
    PublicKey const& public_key, Bytes32 const& hidden_puzzle_hash)
{
  auto synthetic_public_key
      = calculate_synthetic_public_key(public_key, hidden_puzzle_hash);

  return puzzle_for_synthetic_public_key(synthetic_public_key);
}

Program puzzle_for_public_key_and_hidden_puzzle(
    PublicKey const& public_key, Program const& hidden_puzzle)
{
  return puzzle_for_public_key_and_hidden_puzzle_hash(
      public_key, hidden_puzzle.GetTreeHash());
}

Program puzzle_for_pk(PublicKey const& public_key)
{
  return puzzle_for_public_key_and_hidden_puzzle_hash(public_key,
      CLVMPrograms::GetInstance()
          .GetProgram(DEFAULT_HIDDEN_PUZZLE)
          .GetTreeHash());
}

} // namespace puzzle

Address Key::GetAddress() const
{
  auto puzzle_hash = puzzle::puzzle_for_pk(GetPublicKey()).GetTreeHash();
  return bech32::Encode("xch",
      bech32::ConvertBits(
          utils::BytesToInts(utils::bytes_cast<32>(puzzle_hash)), 8, 5));
}

} // namespace wallet
} // namespace chia
