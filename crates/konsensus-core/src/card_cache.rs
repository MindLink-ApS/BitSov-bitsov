//! Verified front-door cards this node holds for other nodes (BROWSE.md §5).
//!
//! Only cards whose signature verifies get in. A higher `seq` replaces a lower
//! one; a lower or equal `seq` is stale and leaves the held card in place, so
//! whoever serves a card can never roll this node back. Expired cards stay
//! (shown "as of") but are never a dial target: `open` demands a fresh card.

use std::collections::BTreeMap;

use crate::front_door::{FrontDoorCard, FrontDoorError};

/// Most cards held at once (worst case 512 × 16 KiB = 8 MiB).
pub const MAX_CACHED_CARDS: usize = 512;

/// What [`CardCache::offer`] did with a verified card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// First card for this node, or a higher `seq` than the one held.
    Stored,
    /// Not newer than the held card, which stays.
    Stale { held_seq: u64 },
}

#[derive(Debug, Default)]
pub struct CardCache {
    cards: BTreeMap<String, FrontDoorCard>,
}

impl CardCache {
    /// Verify `card`'s signature and keep it if it is newer than the held one.
    /// When full, the card that expires first makes room.
    pub fn offer(&mut self, card: FrontDoorCard) -> Result<Offer, FrontDoorError> {
        card.verify_signature()?;
        if let Some(held) = self.cards.get(&card.node_id) {
            if card.seq <= held.seq {
                return Ok(Offer::Stale { held_seq: held.seq });
            }
        } else if self.cards.len() >= MAX_CACHED_CARDS {
            if let Some(first) = self
                .cards
                .values()
                .min_by_key(|c| c.expires_at)
                .map(|c| c.node_id.clone())
            {
                self.cards.remove(&first);
            }
        }
        self.cards.insert(card.node_id.clone(), card);
        Ok(Offer::Stored)
    }

    pub fn get(&self, node_id: &str) -> Option<&FrontDoorCard> {
        self.cards.get(node_id)
    }

    /// Every held card, ordered by node id.
    pub fn list(&self) -> Vec<FrontDoorCard> {
        self.cards.values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.cards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cards.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::front_door::{FrontDoorFields, FrontDoorPrices, FrontDoorProfile, ProfileKind};
    use crate::identity::NodeIdentity;

    fn card(id: &NodeIdentity, seq: u64, issued_at: u64) -> FrontDoorCard {
        FrontDoorCard::issue(
            id,
            FrontDoorFields {
                network: "regtest".into(),
                endpoint: "node.example.org:9000".into(),
                seq,
                issued_at,
                prices: FrontDoorPrices { admission_msat: 2_000, message_msat: 2_000, page_msat: 1_000, price_epoch: 0 },
                profile: FrontDoorProfile {
                    kind: ProfileKind::Person,
                    display_name: format!("seq {seq}"),
                    tagline: String::new(),
                    about: String::new(),
                    avatar: None,
                },
                cv: None,
                media: vec![],
                site: None,
                links: vec![],
            },
        )
        .unwrap()
    }

    fn node() -> NodeIdentity {
        NodeIdentity::generate().unwrap().1
    }

    #[test]
    fn higher_seq_replaces_and_lower_or_equal_is_stale() {
        let id = node();
        let mut cache = CardCache::default();
        assert_eq!(cache.offer(card(&id, 2, 1_700_000_000)).unwrap(), Offer::Stored);
        assert_eq!(cache.offer(card(&id, 1, 1_700_000_100)).unwrap(), Offer::Stale { held_seq: 2 });
        assert_eq!(cache.offer(card(&id, 2, 1_700_000_200)).unwrap(), Offer::Stale { held_seq: 2 });
        let held = cache.get(&card(&id, 2, 0).node_id).unwrap();
        assert_eq!((held.seq, held.issued_at), (2, 1_700_000_000), "a rollback never replaces the held card");
        assert_eq!(cache.offer(card(&id, 3, 1_700_000_300)).unwrap(), Offer::Stored);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_forged_card_is_refused_and_never_held() {
        let id = node();
        let mut cache = CardCache::default();
        let mut forged = card(&id, 9, 1_700_000_000);
        forged.profile.display_name = "someone else".into();
        assert_eq!(cache.offer(forged), Err(FrontDoorError::InvalidSignature));
        assert!(cache.is_empty());
    }

    #[test]
    fn a_full_cache_evicts_the_card_that_expires_first() {
        let mut cache = CardCache::default();
        let base = 1_700_000_000;
        let oldest = node();
        cache.offer(card(&oldest, 1, base)).unwrap();
        for i in 1..MAX_CACHED_CARDS as u64 {
            cache.offer(card(&node(), 1, base + i)).unwrap();
        }
        assert_eq!(cache.len(), MAX_CACHED_CARDS);
        let newcomer = node();
        assert_eq!(cache.offer(card(&newcomer, 1, base + 10_000)).unwrap(), Offer::Stored);
        assert_eq!(cache.len(), MAX_CACHED_CARDS);
        assert!(cache.get(&oldest.node_id().to_hex()).is_none(), "the earliest-expiring card made room");
        assert!(cache.get(&newcomer.node_id().to_hex()).is_some());
    }
}
