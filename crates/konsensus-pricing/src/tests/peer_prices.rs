use super::*;

fn test_node_id(byte: u8) -> NodeId {
    NodeId::from_bytes([byte; 32])
}

#[tokio::test]
async fn cache_store_and_retrieve() {
    let cache = PeerPriceCache::new();
    let peer = test_node_id(1);

    let mut prices = HashMap::new();
    prices.insert("communication".to_string(), 15);
    prices.insert("files_media".to_string(), 150);

    cache.update(peer, prices, 886_000, 144, 0.0).await;

    // KIND_CHAT (0) maps to communication
    assert_eq!(cache.get_peer_price(&peer, 0).await, Some(15));
    // KIND_FILE_REF (200) maps to files_media
    assert_eq!(cache.get_peer_price(&peer, 200).await, Some(150));
    // Unknown peer returns None
    assert_eq!(cache.get_peer_price(&test_node_id(2), 0).await, None);
}

#[tokio::test]
async fn cache_update_replaces() {
    let cache = PeerPriceCache::new();
    let peer = test_node_id(1);

    let mut prices1 = HashMap::new();
    prices1.insert("communication".to_string(), 10);
    cache.update(peer, prices1, 886_000, 144, 0.0).await;

    let mut prices2 = HashMap::new();
    prices2.insert("communication".to_string(), 20);
    cache.update(peer, prices2, 886_100, 144, 0.0).await;

    assert_eq!(cache.get_peer_price(&peer, 0).await, Some(20));

    let entry = cache.get_peer_entry(&peer).await.unwrap();
    assert_eq!(entry.block_height, 886_100);
}

#[tokio::test]
async fn cache_remove() {
    let cache = PeerPriceCache::new();
    let peer = test_node_id(1);

    let mut prices = HashMap::new();
    prices.insert("communication".to_string(), 10);
    cache.update(peer, prices, 886_000, 0, 0.0).await;

    assert_eq!(cache.len().await, 1);
    cache.remove(&peer).await;
    assert_eq!(cache.len().await, 0);
    assert_eq!(cache.get_peer_price(&peer, 0).await, None);
}

#[test]
fn category_string_mapping() {
    assert_eq!(
        category_to_string(KindCategory::Communication),
        "communication"
    );
    assert_eq!(
        category_to_string(KindCategory::FilesMedia),
        "files_media"
    );
    assert_eq!(
        category_to_string(KindCategory::Control),
        "control"
    );
}

#[tokio::test]
async fn staleness_by_block_height() {
    let cache = PeerPriceCache::new();
    let peer = test_node_id(1);

    let mut prices = HashMap::new();
    prices.insert("communication".to_string(), 15);
    // Table computed at block 886_000, valid for 144 blocks
    cache.update(peer, prices, 886_000, 144, 0.0).await;

    let max_age = std::time::Duration::from_secs(86400);

    // Current height within validity window → fresh
    assert_eq!(
        cache.get_fresh_peer_price(&peer, 0, 886_100, max_age).await,
        Some(15)
    );
    // Current height at exact expiry → still valid (not strictly greater)
    assert_eq!(
        cache.get_fresh_peer_price(&peer, 0, 886_144, max_age).await,
        Some(15)
    );
    // Current height past expiry → stale, returns None
    assert_eq!(
        cache.get_fresh_peer_price(&peer, 0, 886_145, max_age).await,
        None
    );
}

#[tokio::test]
async fn staleness_zero_valid_blocks_never_stale_by_height() {
    let cache = PeerPriceCache::new();
    let peer = test_node_id(1);

    let mut prices = HashMap::new();
    prices.insert("communication".to_string(), 10);
    // valid_blocks = 0 means "valid until replaced"
    cache.update(peer, prices, 886_000, 0, 0.0).await;

    let max_age = std::time::Duration::from_secs(86400);

    // Even far in the future, not stale by block height
    assert_eq!(
        cache.get_fresh_peer_price(&peer, 0, 1_000_000, max_age).await,
        Some(10)
    );
}

#[test]
fn entry_staleness_wall_clock() {
    let entry = PeerPriceEntry {
        prices: {
            let mut p = HashMap::new();
            p.insert("communication".to_string(), 10);
            p
        },
        block_height: 886_000,
        valid_blocks: 0,
        // Use Instant::now() — it's always "just received"
        received_at: Instant::now(),
        trust_discount: 0.0,
    };
    // With a very long max_age, not stale
    assert!(!entry.is_stale(886_000, std::time::Duration::from_secs(86400)));
    // With zero max_age, always stale
    assert!(entry.is_stale(886_000, std::time::Duration::ZERO));
}

#[tokio::test]
async fn all_entries_returns_all() {
    let cache = PeerPriceCache::new();
    let peer1 = test_node_id(1);
    let peer2 = test_node_id(2);

    let mut p1 = HashMap::new();
    p1.insert("communication".to_string(), 10);
    cache.update(peer1, p1, 886_000, 144, 0.0).await;

    let mut p2 = HashMap::new();
    p2.insert("communication".to_string(), 20);
    cache.update(peer2, p2, 886_100, 72, 0.0).await;

    let all = cache.all_entries().await;
    assert_eq!(all.len(), 2);
    assert_eq!(
        all.get(&peer1).unwrap().prices.get("communication"),
        Some(&10)
    );
    assert_eq!(
        all.get(&peer2).unwrap().prices.get("communication"),
        Some(&20)
    );
}

#[tokio::test]
async fn missing_category_returns_none() {
    let cache = PeerPriceCache::new();
    let peer = test_node_id(1);

    // Only set communication pricing
    let mut prices = HashMap::new();
    prices.insert("communication".to_string(), 10);
    cache.update(peer, prices, 886_000, 0, 0.0).await;

    // KIND_FILE_REF (200) maps to files_media, which isn't in the table
    assert_eq!(cache.get_peer_price(&peer, 200).await, None);
}

#[tokio::test]
async fn update_kind_price_updates_existing_entry() {
    let cache = PeerPriceCache::new();
    let peer = test_node_id(1);

    // Start with a full price table
    let mut prices = HashMap::new();
    prices.insert("communication".to_string(), 10);
    prices.insert("files_media".to_string(), 100);
    cache.update(peer, prices, 886_000, 144, 0.0).await;

    // Update just the communication price via PriceResponse
    cache
        .update_kind_price(peer, 0, 25, 886_050)
        .await;

    // Communication should be updated
    assert_eq!(cache.get_peer_price(&peer, 0).await, Some(25));
    // Files should be unchanged
    assert_eq!(cache.get_peer_price(&peer, 200).await, Some(100));
    // Block height should be updated
    let entry = cache.get_peer_entry(&peer).await.unwrap();
    assert_eq!(entry.block_height, 886_050);
}

#[tokio::test]
async fn update_kind_price_creates_new_entry() {
    let cache = PeerPriceCache::new();
    let peer = test_node_id(1);

    // No existing entry — PriceResponse creates one
    cache
        .update_kind_price(peer, 0, 15, 886_000)
        .await;

    assert_eq!(cache.get_peer_price(&peer, 0).await, Some(15));
    assert_eq!(cache.len().await, 1);
    // Other categories should be None
    assert_eq!(cache.get_peer_price(&peer, 200).await, None);
}

// ── compute_valid_blocks tests ─────────────────────────────────────

#[test]
fn valid_blocks_zero_height_conservative() {
    // Unknown chain state → conservative validity
    assert_eq!(compute_valid_blocks(0), 72);
}

#[test]
fn valid_blocks_post_adjustment() {
    // Blocks 0–100 within a 2016-block epoch → post-adjustment (settling)
    assert_eq!(compute_valid_blocks(2016 * 10), 72); // Exactly at adjustment
    assert_eq!(compute_valid_blocks(2016 * 10 + 1), 72); // 1 block after
    assert_eq!(compute_valid_blocks(2016 * 10 + 50), 72); // 50 blocks after
    assert_eq!(compute_valid_blocks(2016 * 10 + 100), 72); // 100 blocks after
}

#[test]
fn valid_blocks_mid_epoch_stable() {
    // Blocks 101–1915 → mid-epoch, stable period, longest validity
    assert_eq!(compute_valid_blocks(2016 * 10 + 101), 144);
    assert_eq!(compute_valid_blocks(2016 * 10 + 500), 144);
    assert_eq!(compute_valid_blocks(2016 * 10 + 1000), 144);
    assert_eq!(compute_valid_blocks(2016 * 10 + 1915), 144);
}

#[test]
fn valid_blocks_pre_adjustment() {
    // Blocks 1916–2015 → pre-adjustment, shortest validity
    assert_eq!(compute_valid_blocks(2016 * 10 + 1916), 36);
    assert_eq!(compute_valid_blocks(2016 * 10 + 2000), 36);
    assert_eq!(compute_valid_blocks(2016 * 10 + 2015), 36);
}

#[test]
fn valid_blocks_at_current_bitcoin_height() {
    // Test with a realistic current block height (886,000)
    let pos = 886_000 % 2016; // = 1136, which is mid-epoch
    assert!(pos > 100 && pos < 1916);
    assert_eq!(compute_valid_blocks(886_000), 144);
}

#[test]
fn valid_blocks_boundary_transitions() {
    // Exact boundary: block 100 → still post-adjustment
    assert_eq!(compute_valid_blocks(100), 72);
    // Block 101 → transitions to mid-epoch
    assert_eq!(compute_valid_blocks(101), 144);
    // Block 1915 → still mid-epoch
    assert_eq!(compute_valid_blocks(1915), 144);
    // Block 1916 → transitions to pre-adjustment
    assert_eq!(compute_valid_blocks(1916), 36);
}

// ── build_full_price_table tests ───────────────────────────────────

#[tokio::test]
async fn full_price_table_metadata() {
    use konsensus_chain::MockChainProvider;
    use konsensus_core::traits::chain::TrustLevel;

    let pricing = crate::StaticPricingEngine::new(crate::StaticPricingConfig::default());
    let chain = MockChainProvider::new(); // height ~886,000

    let meta = build_full_price_table(&pricing, &chain).await;

    // Should have all priceable categories
    assert!(meta.prices.contains_key("communication"));
    assert!(meta.prices.contains_key("files_media"));
    assert!(meta.prices.contains_key("control"));
    assert!(meta.prices.len() >= 6);

    // Block height should be near the mock's initial value
    assert!(meta.block_height >= 886_000);

    // valid_blocks should be computed from difficulty epoch
    let epoch_pos = meta.block_height % 2016;
    let expected = if epoch_pos <= 100 {
        72
    } else if epoch_pos >= 1916 {
        36
    } else {
        144
    };
    assert_eq!(meta.valid_blocks, expected);

    // Mock provider reports ServerTrust
    assert_eq!(meta.trust_level, TrustLevel::ServerTrust);
}

// ── apply_trust_discount NaN/Infinity safety tests ────────────────

#[test]
fn trust_discount_nan_returns_full_price() {
    // NaN discount must return full base price, not 1 msat.
    // A 1 msat result would effectively bypass the payment gate.
    assert_eq!(apply_trust_discount(1000, f64::NAN), 1000);
}

#[test]
fn trust_discount_positive_infinity_returns_full_price() {
    assert_eq!(apply_trust_discount(1000, f64::INFINITY), 1000);
}

#[test]
fn trust_discount_negative_infinity_returns_full_price() {
    assert_eq!(apply_trust_discount(1000, f64::NEG_INFINITY), 1000);
}

#[test]
fn trust_discount_normal_values() {
    // Zero discount → full price
    assert_eq!(apply_trust_discount(1000, 0.0), 1000);
    // 50% discount → ceil(500) = 500
    assert_eq!(apply_trust_discount(1000, 0.5), 500);
    // 25% discount → ceil(750) = 750
    assert_eq!(apply_trust_discount(1000, 0.25), 750);
    // Negative discount clamped to 0.0 → full price
    assert_eq!(apply_trust_discount(1000, -0.5), 1000);
    // Discount > MAX clamped to 0.5 → 500
    assert_eq!(apply_trust_discount(1000, 0.9), 500);
}

#[test]
fn trust_discount_minimum_1_msat() {
    // Even with maximum discount on tiny base, never returns 0
    assert_eq!(apply_trust_discount(1, 0.5), 1);
}

// ── HARD-13: double-discount / floor post-condition tests ─────────

#[test]
fn floor_is_max_discount_of_base() {
    // The floor for a base price is base * (1 - MAX_TRUST_DISCOUNT), ceil'd,
    // and never below 1 msat.
    assert_eq!(trust_discount_floor_msat(1000), 500);
    assert_eq!(trust_discount_floor_msat(3), 2); // ceil(1.5)
    assert_eq!(trust_discount_floor_msat(1), 1); // ceil(0.5) → 1, min 1
    assert_eq!(trust_discount_floor_msat(0), 1); // never free
}

#[test]
fn no_single_discount_path_falls_below_floor() {
    // For a representative spread of base prices, NO discount value — including
    // out-of-range, negative, and the maximum — may produce a price below the
    // per-base floor. This is the core money-path invariant.
    let bases = [1u64, 2, 3, 7, 10, 100, 999, 1000, 1_000_000, u64::MAX / 2];
    let discounts = [
        -1.0,
        0.0,
        0.1,
        0.25,
        0.5,
        0.9, // clamped to MAX_TRUST_DISCOUNT
        1.0, // clamped
        100.0, // clamped
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ];
    for &base in &bases {
        let floor = trust_discount_floor_msat(base);
        for &d in &discounts {
            let price = apply_trust_discount(base, d);
            assert!(
                price >= floor,
                "base={base} discount={d} price={price} dipped below floor={floor}"
            );
            // And never free.
            assert!(price >= 1, "base={base} discount={d} produced 0 msat");
        }
    }
}

#[test]
fn discount_applied_once_equals_half_at_max() {
    // A correct single application at the maximum discount equals the floor.
    assert_eq!(apply_trust_discount(1000, MAX_TRUST_DISCOUNT), 500);
    assert_eq!(apply_trust_discount(1000, MAX_TRUST_DISCOUNT), trust_discount_floor_msat(1000));
}

#[test]
fn double_applied_discount_breaches_original_floor() {
    // This is the harm the single-choke-point design prevents. If a caller
    // applied the discount TWICE on the same logical message (the HARD-13 bug),
    // the effective price compounds to base * (1 - d)^2, which falls strictly
    // below the original base's floor of base * (1 - d). We assert that the
    // compounded value WOULD breach the floor — documenting why no production
    // path may apply the discount more than once.
    let base = 1000u64;
    let floor = trust_discount_floor_msat(base); // 500

    let once = apply_trust_discount(base, MAX_TRUST_DISCOUNT); // 500
    assert_eq!(once, floor);

    // Compounding: feed the discounted price back through the choke point.
    let twice = apply_trust_discount(once, MAX_TRUST_DISCOUNT); // 250
    assert!(
        twice < floor,
        "double application ({twice}) must fall below the original floor ({floor}); \
         the single choke point is what prevents this in production"
    );
    assert_eq!(twice, 250);
}

#[test]
fn single_application_never_breaches_its_own_floor() {
    // The post-condition guarantee: for ANY base and ANY discount, a single
    // application stays at or above that base's floor. Exhaustively checked for
    // a representative spread; the function's debug_assert + release clamp make
    // this a hard invariant rather than an incidental property.
    for base in [1u64, 5, 999, 1000, 7_777, 1_000_000] {
        let floor = trust_discount_floor_msat(base);
        for d in [0.0, 0.25, 0.5, 0.499_999, MAX_TRUST_DISCOUNT] {
            assert!(apply_trust_discount(base, d) >= floor);
        }
    }
}

#[tokio::test]
async fn bundled_getter_applies_discount_exactly_once() {
    let cache = PeerPriceCache::new();
    let peer = test_node_id(1);

    let mut prices = HashMap::new();
    prices.insert("communication".to_string(), 1000);
    // Maximum trust discount.
    cache.update(peer, prices, 886_000, 144, MAX_TRUST_DISCOUNT).await;

    let max_age = std::time::Duration::from_secs(86400);

    // Bundled choke-point getter: base 1000 at 0.5 discount → 500, applied once.
    let discounted = cache
        .get_fresh_discounted_peer_price(&peer, 0, 886_100, max_age)
        .await;
    assert_eq!(discounted, Some(500));

    // The undiscounted base getter still returns the full price, proving the
    // discount lives only in the bundled path (no compounding).
    assert_eq!(
        cache.get_fresh_peer_price(&peer, 0, 886_100, max_age).await,
        Some(1000)
    );

    // The bundled result must never fall below the floor.
    let floor = trust_discount_floor_msat(1000);
    assert!(discounted.unwrap() >= floor);
}

#[tokio::test]
async fn bundled_getter_stale_table_returns_none() {
    let cache = PeerPriceCache::new();
    let peer = test_node_id(1);

    let mut prices = HashMap::new();
    prices.insert("communication".to_string(), 1000);
    cache.update(peer, prices, 886_000, 144, MAX_TRUST_DISCOUNT).await;

    let max_age = std::time::Duration::from_secs(86400);

    // Past block-height expiry → stale → None (caller falls back to own pricing).
    assert_eq!(
        cache
            .get_fresh_discounted_peer_price(&peer, 0, 886_145, max_age)
            .await,
        None
    );
}

// ── compute_trust_discount NaN/Infinity safety tests ──────────────

#[test]
fn compute_discount_nan_weight_returns_zero() {
    assert_eq!(compute_trust_discount(f64::NAN), 0.0);
}

#[test]
fn compute_discount_infinity_weight_returns_zero() {
    assert_eq!(compute_trust_discount(f64::INFINITY), 0.0);
    assert_eq!(compute_trust_discount(f64::NEG_INFINITY), 0.0);
}

#[test]
fn compute_discount_normal_weights() {
    assert_eq!(compute_trust_discount(0.0), 0.0);
    assert_eq!(compute_trust_discount(1.0), MAX_TRUST_DISCOUNT);
    assert_eq!(compute_trust_discount(0.5), MAX_TRUST_DISCOUNT * 0.5);
}
