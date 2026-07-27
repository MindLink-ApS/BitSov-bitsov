//! Benchmarks for the Synaptic Routing Protocol.
//!
//! Tests routing decision performance at scale to verify O(N) peer lookup
//! and O(1) weight updates work within the mesh's real-time requirements.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use konsensus_core::types::NodeId;
use konsensus_routing::{RoutingTable, SynapticWeight};
use tokio::runtime::Runtime;

fn node_id(byte: u8) -> NodeId {
    NodeId::from_bytes([byte; 32])
}

/// Unique NodeId from a u16 — fills first 2 bytes distinctly.
fn node_id_u16(n: u16) -> NodeId {
    let mut bytes = [0u8; 32];
    bytes[0] = (n >> 8) as u8;
    bytes[1] = (n & 0xff) as u8;
    bytes[2] = 0x01; // Distinguish from zero-filled
    NodeId::from_bytes(bytes)
}

fn bench_weight_record_success(c: &mut Criterion) {
    c.bench_function("SynapticWeight::record_success", |b| {
        let mut w = SynapticWeight::new();
        b.iter(|| {
            w.record_success(black_box(50.0), black_box(1000));
        });
    });
}

fn bench_weight_record_failure(c: &mut Criterion) {
    c.bench_function("SynapticWeight::record_failure", |b| {
        let mut w = SynapticWeight::new();
        b.iter(|| {
            w.record_failure();
        });
    });
}

fn bench_weight_routing_score(c: &mut Criterion) {
    c.bench_function("SynapticWeight::routing_score", |b| {
        let mut w = SynapticWeight::new();
        for _ in 0..100 {
            w.record_success(50.0, 1000);
        }
        b.iter(|| {
            black_box(w.routing_score());
        });
    });
}

fn bench_weight_apply_decay(c: &mut Criterion) {
    c.bench_function("SynapticWeight::apply_decay", |b| {
        let mut w = SynapticWeight::new();
        w.record_success(50.0, 1000);
        b.iter(|| {
            w.apply_decay();
        });
    });
}

fn bench_route_to(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("RoutingTable::route_to");

    for peer_count in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{peer_count}_peers")),
            &peer_count,
            |b, &count| {
                let table = rt.block_on(async {
                    let t = RoutingTable::with_defaults();
                    for i in 0..count {
                        let peer = node_id_u16(i);
                        t.record_success(&peer, (i as f64 + 1.0) * 10.0, 1000).await;
                    }
                    t
                });
                let dest = node_id(0xff);
                b.iter(|| {
                    rt.block_on(async {
                        black_box(table.route_to(&dest).await);
                    });
                });
            },
        );
    }
    group.finish();
}

fn bench_record_success_table(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("RoutingTable::record_success", |b| {
        let table = rt.block_on(async {
            let t = RoutingTable::with_defaults();
            for i in 0..100u16 {
                t.record_success(&node_id_u16(i), 50.0, 1000).await;
            }
            t
        });
        let peer = node_id(1);
        b.iter(|| {
            rt.block_on(async {
                table.record_success(black_box(&peer), black_box(42.0), black_box(500)).await;
            });
        });
    });
}

fn bench_decay_all(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("RoutingTable::decay_all");

    for peer_count in [10, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{peer_count}_peers")),
            &peer_count,
            |b, &count| {
                let table = rt.block_on(async {
                    let t = RoutingTable::with_defaults();
                    for i in 0..count {
                        t.record_success(&node_id_u16(i), 50.0, 1000).await;
                    }
                    t
                });
                b.iter(|| {
                    rt.block_on(async {
                        table.decay_all().await;
                    });
                });
            },
        );
    }
    group.finish();
}

fn bench_peer_scores(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("RoutingTable::peer_scores (100 peers)", |b| {
        let table = rt.block_on(async {
            let t = RoutingTable::with_defaults();
            for i in 0..100u16 {
                t.record_success(&node_id_u16(i), 50.0, 1000).await;
            }
            t
        });
        b.iter(|| {
            rt.block_on(async {
                black_box(table.peer_scores().await);
            });
        });
    });
}

criterion_group!(
    benches,
    bench_weight_record_success,
    bench_weight_record_failure,
    bench_weight_routing_score,
    bench_weight_apply_decay,
    bench_route_to,
    bench_record_success_table,
    bench_decay_all,
    bench_peer_scores,
);
criterion_main!(benches);
