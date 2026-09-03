//! The same peer, named two ways.
//!
//! discv5 identifies a node by its Kademlia node id, the keccak256 of its
//! uncompressed secp256k1 public key. libp2p identifies the same node by a
//! [`PeerId`], a multihash of the protobuf encoding of that same key. Both are
//! derived from one key, so either name can be computed from it, and ethlambda
//! needs the round trip in both directions:
//!
//! - reading an ENR, to key a dial target by the node id ethrex will later name
//!   it with ([`node_id_from_public_key`]);
//! - reporting a live connection, where all the swarm gives us is a `PeerId`
//!   ([`node_id_from_peer_id`]).

use ethrex_common::{H256, H512};
use ethrex_p2p::utils::node_id;
use libp2p::PeerId;
use libp2p::identity::secp256k1::PublicKey;

/// Multihash code under which libp2p inlines a public key rather than hashing
/// it. Keys short enough to fit are stored verbatim, which is what makes the
/// key recoverable from a `PeerId` at all.
const IDENTITY_MULTIHASH_CODE: u64 = 0x00;

/// The discv5 node id for a libp2p secp256k1 key.
///
/// ethrex hashes the 64-byte uncompressed point, so the `0x04` prefix libp2p
/// emits is dropped first.
pub(crate) fn node_id_from_public_key(key: &PublicKey) -> H256 {
    node_id(&H512::from_slice(&key.to_bytes_uncompressed()[1..]))
}

/// The discv5 node id behind a `PeerId`, or `None` when the peer id does not
/// carry a secp256k1 key we can read back.
///
/// A `PeerId` is a hash of the key in general, but libp2p inlines any encoding
/// short enough, and a secp256k1 key always is. Lean's spec mandates secp256k1
/// for the libp2p identity, so the `None` arm covers a peer speaking something
/// else: nothing to report about it, rather than an error.
pub(crate) fn node_id_from_peer_id(peer_id: &PeerId) -> Option<H256> {
    let multihash = peer_id.as_ref();
    if multihash.code() != IDENTITY_MULTIHASH_CODE {
        return None;
    }
    let key = libp2p::identity::PublicKey::try_decode_protobuf(multihash.digest()).ok()?;
    Some(node_id_from_public_key(&key.try_into_secp256k1().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn a_peer_id_resolves_to_the_node_id_of_the_key_behind_it() {
        let keypair = Keypair::generate_secp256k1();
        let key = keypair.public().try_into_secp256k1().expect("secp256k1");
        let peer_id = PeerId::from_public_key(&keypair.public());

        // The two directions must agree, or a peer admitted from its ENR and the
        // same peer seen connecting would be reported under different ids: the
        // connected set would count it twice and never drop it on disconnect.
        assert_eq!(
            node_id_from_peer_id(&peer_id),
            Some(node_id_from_public_key(&key))
        );
    }

    #[test]
    fn a_non_secp256k1_peer_id_has_no_node_id() {
        // ed25519 keys are also short enough to be inlined, so this reaches the
        // key decode rather than being turned away by the multihash code.
        let peer_id = PeerId::from_public_key(&Keypair::generate_ed25519().public());

        assert_eq!(node_id_from_peer_id(&peer_id), None);
    }

    #[test]
    fn a_hashed_peer_id_has_no_node_id() {
        // `PeerId::random` produces a sha256 multihash, the form a long key
        // takes. There is no key inside it to recover.
        assert_eq!(node_id_from_peer_id(&PeerId::random()), None);
    }
}
