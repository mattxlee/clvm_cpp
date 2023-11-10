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

/// adapters for converting data from bls data types

namespace adapters {

template <typename V, typename C, typename F>
std::vector<V> convert_container(C const& c, F&& f) {
    std::vector<V> result;
    std::transform(std::cbegin(c), std::cend(c), std::back_inserter(result), f);
    return result;
}

bls::G1Element public_key_to_g1(PublicKey const& public_key) {
    return bls::G1Element::FromByteVector(utils::bytes_cast<Key::PUB_KEY_LEN>(public_key));
}

PublicKey public_key_from_g1(bls::G1Element const& g1) {
    return utils::bytes_cast<Key::PUB_KEY_LEN>(g1.Serialize());
}

bls::G2Element signature_to_g2(Signature const& signature) {
    return bls::G2Element::FromByteVector(utils::bytes_cast<Key::SIG_LEN>(signature));
}

Signature signature_from_g2(bls::G2Element const& g2) {
    return utils::bytes_cast<Key::SIG_LEN>(g2.Serialize());
}

PrivateKey private_key_from_bls_private_key(bls::PrivateKey const& private_key) {
    return utils::bytes_cast<Key::PRIV_KEY_LEN>(private_key.Serialize());
}

bls::PrivateKey private_key_to_bls_private_key(PrivateKey const& private_key) {
    return bls::PrivateKey::FromByteVector(utils::bytes_cast<Key::PRIV_KEY_LEN>(private_key));
}

} // namespace adapters

bool Key::VerifySignature(PublicKey const& public_key, Bytes const& message, Signature const& signature)
{
    return bls::AugSchemeMPL().Verify(adapters::public_key_to_g1(public_key), message, adapters::signature_to_g2(signature));
}

PublicKey Key::AggregatePublicKeys(std::vector<PublicKey> const& public_keys)
{
    std::vector<bls::G1Element> pks = adapters::convert_container<bls::G1Element>(public_keys, adapters::public_key_to_g1);
    auto agg_pk = bls::AugSchemeMPL().Aggregate(pks);
    return utils::bytes_cast<PUB_KEY_LEN>(agg_pk.Serialize());
}

Signature Key::AggregateSignatures(std::vector<Signature> const& signatures)
{
    std::vector<bls::G2Element> sigs = adapters::convert_container<bls::G2Element>(signatures, adapters::signature_to_g2);
    auto agg_sig = bls::AugSchemeMPL().Aggregate(sigs);
    return utils::bytes_cast<SIG_LEN>(agg_sig.Serialize());
}

bool Key::AggregateVerifySignature(std::vector<PublicKey> const& public_keys, std::vector<Bytes> const& messages, Signature const& signature)
{
    std::vector<bls::G1Element> pks = adapters::convert_container<bls::G1Element>(public_keys, adapters::public_key_to_g1);
    return bls::AugSchemeMPL().AggregateVerify(pks, messages, adapters::signature_to_g2(signature));
}

Key::Key() { }

Key::Key(PrivateKey priv_key)
    : priv_key_(std::move(priv_key))
{
}

Key::Key(Bytes const& seed)
{
    auto seed_bytes = utils::BytesToHex(seed);
    priv_key_ = adapters::private_key_from_bls_private_key(bls::AugSchemeMPL().KeyGen(seed));
}

bool Key::IsEmpty() const { return priv_key_.empty(); }

void Key::GenerateNew(Bytes const& seed)
{
    priv_key_ = adapters::private_key_from_bls_private_key(bls::AugSchemeMPL().KeyGen(seed));
}

PrivateKey const& Key::GetPrivateKey() const { return priv_key_; }

PublicKey Key::GetPublicKey() const
{
    auto bls_priv_key = adapters::private_key_to_bls_private_key(priv_key_);
    return adapters::public_key_from_g1(bls_priv_key.GetG1Element());
}

Signature Key::Sign(Bytes const& message)
{
    auto bls_priv_key = adapters::private_key_to_bls_private_key(priv_key_);
    return adapters::signature_from_g2(bls::AugSchemeMPL().Sign(bls_priv_key, message));
}

Key Key::DerivePath(std::vector<uint32_t> const& paths, bool unhardened) const
{
    auto bls_priv_key = adapters::private_key_to_bls_private_key(priv_key_);
    auto sk { bls_priv_key };
    for (uint32_t path : paths) {
        if (unhardened) {
            sk = bls::AugSchemeMPL().DeriveChildSkUnhardened(sk, path);
        } else {
            sk = bls::AugSchemeMPL().DeriveChildSk(sk, path);
        }
    }
    return Key(utils::bytes_cast<PRIV_KEY_LEN>(sk.Serialize()));
}

Key Key::GetWalletKey(uint32_t index, bool unhardened) const
{
    return DerivePath({ 12381, 8444, 2, index });
}

Key Key::GetFarmerKey(uint32_t index, bool unhardened) const
{
    return DerivePath({ 12381, 8444, 0, index });
}

Key Key::GetPoolKey(uint32_t index, bool unhardened) const
{
    return DerivePath({ 12381, 8444, 1, index });
}

Key Key::GetLocalKey(uint32_t index, bool unhardened) const
{
    return DerivePath({ 12381, 8444, 3, index });
}

Key Key::GetBackupKey(uint32_t index, bool unhardened) const
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
