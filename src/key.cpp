#include "key.h"

#include <schemes.hpp>
#include <elements.hpp>

#include <map>

#include "utils.h"

#include "bech32.h"
#include "puzzle.h"

namespace chia
{
namespace wallet
{

bool Key::VerifySig(PublicKey const& pub_key, Bytes const& msg, Signature const& sig)
{
    return bls::AugSchemeMPL().Verify(utils::bytes_cast<PUB_KEY_LEN>(pub_key), msg, utils::bytes_cast<SIG_LEN>(sig));
}

PubKey::PubKey() { pubkey_ = utils::bytes_cast<Key::PUB_KEY_LEN>(bls::G1Element().Serialize()); }

PubKey::PubKey(PublicKey pubkey)
    : pubkey_(std::move(pubkey))
{
}

PubKey PubKey::operator+(PubKey const& rhs) const
{
    auto lhs_g1 = bls::G1Element::FromBytes(bls::Bytes(pubkey_.data(), pubkey_.size()));
    auto rhs_g1 = bls::G1Element::FromBytes(bls::Bytes(rhs.pubkey_.data(), rhs.pubkey_.size()));
    auto res = bls::AugSchemeMPL().Aggregate({ lhs_g1, rhs_g1 });
    return PubKey(utils::bytes_cast<Key::PUB_KEY_LEN>(res.Serialize()));
}

PubKey& PubKey::operator+=(PubKey const& rhs)
{
    *this = *this + rhs;
    return *this;
}

PublicKey const& PubKey::GetPublicKey() const { return pubkey_; }

PublicKey Key::CreatePublicKey() { return utils::bytes_cast<PUB_KEY_LEN>(bls::G1Element().Serialize()); }

PublicKey Key::AddTwoPubkey(PublicKey const& lhs, PublicKey const& rhs)
{
    bls::G1Element g1lhs = bls::G1Element::FromBytes(bls::Bytes(lhs.data(), lhs.size()));
    bls::G1Element g1rhs = bls::G1Element::FromBytes(bls::Bytes(rhs.data(), rhs.size()));
    auto res = g1lhs + g1rhs;
    return utils::bytes_cast<PUB_KEY_LEN>(res.Serialize());
}

Key::Key() { }

Key::Key(PrivateKey priv_key)
    : priv_key_(std::move(priv_key))
{
}

Key::Key(Bytes const& seed)
{
    auto seed_bytes = utils::BytesToHex(seed);
    priv_key_ = utils::bytes_cast<PRIV_KEY_LEN>(bls::AugSchemeMPL().KeyGen(seed).Serialize());
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
    bls::PrivateKey bls_priv_key = bls::PrivateKey::FromBytes(bls::Bytes(utils::bytes_cast<PRIV_KEY_LEN>(priv_key_)));
    return utils::bytes_cast<PUB_KEY_LEN>(bls_priv_key.GetG1Element().Serialize());
}

Signature Key::Sign(Bytes const& msg)
{
    bls::PrivateKey bls_priv_key = bls::PrivateKey::FromBytes(bls::Bytes(utils::bytes_cast<PRIV_KEY_LEN>(priv_key_)));
    Bytes sig_bytes = bls::AugSchemeMPL().Sign(bls_priv_key, msg).Serialize();
    return utils::bytes_cast<SIG_LEN>(sig_bytes);
}

Key Key::DerivePath(std::vector<uint32_t> const& paths) const
{
    bls::PrivateKey bls_priv_key = bls::PrivateKey::FromBytes(bls::Bytes(utils::bytes_cast<PRIV_KEY_LEN>(priv_key_)));
    auto sk { bls_priv_key };
    for (uint32_t path : paths) {
        sk = bls::AugSchemeMPL().DeriveChildSk(sk, path);
    }
    return Key(utils::bytes_cast<PRIV_KEY_LEN>(sk.Serialize()));
}

Key Key::GetWalletKey(uint32_t index) const
{
    return DerivePath({ 12381, 8444, 2, index });
}

Key Key::GetFarmerKey(uint32_t index) const
{
    return DerivePath({ 12381, 8444, 0, index });
}

Key Key::GetPoolKey(uint32_t index) const
{
    return DerivePath({ 12381, 8444, 1, index });
}

Key Key::GetLocalKey(uint32_t index) const
{
    return DerivePath({ 12381, 8444, 3, index });
}

Key Key::GetBackupKey(uint32_t index) const
{
    return DerivePath({ 12381, 8444, 4, index });
}

Address Key::GetAddress(std::string_view prefix) const
{
    auto puzzle_hash = utils::BytesToInts(utils::HashToBytes(puzzle::puzzle_for_public_key(GetPublicKey()).GetTreeHash()));
    return bech32::EncodePuzzleHash(puzzle_hash, prefix);
}

} // namespace wallet

} // namespace chia
