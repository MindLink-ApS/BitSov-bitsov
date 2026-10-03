//! Codex delta3 (#131): a fresh kind-400 answer and its price are published
//! together. The reviewer's probe, kept as a regression.

use std::{sync::Arc, time::{Duration, Instant}};
use konsensus_core::types::NodeId;
use konsensus_pricing::peer_prices::PeerPriceCache;
use tokio::sync::Barrier;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_call_price_answer_is_never_paired_with_the_previous_price() {
    let cache = Arc::new(PeerPriceCache::new());
    let peer = NodeId::from_bytes([0x6d; 32]);
    let barrier = Arc::new(Barrier::new(2));
    let c = cache.clone();
    let b = barrier.clone();
    let writer = tokio::spawn(async move {
        for _ in 0..100_000 {
            c.update_kind_price(peer, 400, 10_000, 850_000).await;
            b.wait().await;
            b.wait().await;
            c.update_kind_price(peer, 400, 20_000, 850_000).await;
            b.wait().await;
        }
    });
    let mut stale = 0;
    for iteration in 0..100_000 {
        barrier.wait().await;
        let asked = Instant::now();
        barrier.wait().await;
        loop {
            if cache.kind_answered_at(&peer, 400).await.is_some_and(|at| at >= asked) {
                break;
            }
            std::hint::spin_loop();
        }
        let actual = cache.get_fresh_discounted_peer_price(&peer, 400, 850_000, Duration::from_secs(60)).await;
        if actual != Some(20_000) {
            stale += 1;
            if stale == 1 { eprintln!("fresh kind-400 answer exposed previous price {actual:?} at iteration {iteration}"); }
        }
        barrier.wait().await;
    }
    writer.await.unwrap();
    eprintln!("stale reads: {stale} / 100000");
    assert_eq!(stale, 0, "fresh kind-400 answer must expose its updated price");
}
