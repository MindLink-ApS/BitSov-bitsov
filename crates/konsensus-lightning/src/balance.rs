//! LDK balance accounting with injected funding verification and no wallet mutations.

use konsensus_core::traits::lightning::{LightningError, WalletBalanceBreakdown};
use ldk_node::lightning::ln::types::ChannelId;
use ldk_node::{BalanceDetails, LightningBalance, PendingSweepBalance};
use std::collections::HashSet;

/// Validate removed-channel funding before either aggregate or breakdown reads.
/// The resolver uses the configured chain source; errors never mean zero funds.
pub(crate) async fn verify_closed_funding<F, Fut>(
    balances: &mut BalanceDetails,
    open: &HashSet<ChannelId>,
    mut resolve: F,
) -> Result<(), LightningError>
where
    F: FnMut(ChannelId) -> Fut,
    Fut: std::future::Future<Output = Result<bool, LightningError>>,
{
    let removed: HashSet<_> = balances.lightning_balances.iter().filter_map(|balance| {
        match balance {
            LightningBalance::ClaimableOnChannelClose { channel_id, .. }
                if !open.contains(channel_id) => Some(*channel_id),
            _ => None,
        }
    }).collect();
    let mut confirmed = HashSet::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for channel_id in removed {
            if resolve(channel_id).await? { confirmed.insert(channel_id); }
        }
        Ok::<_, LightningError>(())
    }).await.map_err(|_| LightningError::Backend("channel funding verification timed out".into()))??;
    filter_unfunded_closures(balances, open, &confirmed);
    Ok(())
}

/// Explicit absence/unconfirmed is different from failed verification.
pub(crate) fn decode_funding_status(status: u16, body: &[u8]) -> Result<bool, LightningError> {
    if status == 404 { return Ok(false); }
    if status != 200 {
        return Err(LightningError::Backend("funding status backend refused request".into()));
    }
    #[derive(serde::Deserialize)]
    struct FundingStatus { confirmed: bool }
    serde_json::from_slice::<FundingStatus>(body).map(|status| status.confirmed)
        .map_err(|_| LightningError::Backend("invalid funding status response".into()))
}

/// Remove claims without confirmed funding from both balance representations.
pub(crate) fn filter_unfunded_closures(
    balances: &mut BalanceDetails,
    open: &HashSet<ChannelId>,
    confirmed: &HashSet<ChannelId>,
) {
    balances.lightning_balances.retain(|balance| {
        if let LightningBalance::ClaimableOnChannelClose { channel_id, amount_satoshis, .. } = balance {
            if !open.contains(channel_id) && !confirmed.contains(channel_id) {
                balances.total_lightning_balance_sats = balances.total_lightning_balance_sats
                    .saturating_sub(*amount_satoshis);
                return false;
            }
        }
        true
    });
}

/// Channels supply their ID, usability, and outbound capacity in millisatoshis.
pub(crate) fn breakdown(
    balances: &BalanceDetails,
    channels: impl IntoIterator<Item = (ChannelId, bool, u64)>,
) -> WalletBalanceBreakdown {
    let mut open_channels = HashSet::new();
    let mut outbound_msat = 0u128;
    for (id, usable, capacity_msat) in channels {
        open_channels.insert(id);
        if usable {
            outbound_msat += u128::from(capacity_msat);
        }
    }

    let mut closing = 0u128;
    let mut contested = 0u128;
    for balance in &balances.lightning_balances {
        match balance {
            LightningBalance::ClaimableOnChannelClose {
                channel_id,
                amount_satoshis,
                ..
            } => {
                // Force-close removes the channel from the manager before the
                // commitment confirms. A disconnected but open channel stays listed.
                if !open_channels.contains(channel_id) {
                    closing += u128::from(*amount_satoshis);
                }
            }
            LightningBalance::ClaimableAwaitingConfirmations {
                amount_satoshis, ..
            } => {
                closing += u128::from(*amount_satoshis);
            }
            LightningBalance::ContentiousClaimable {
                amount_satoshis, ..
            }
            | LightningBalance::MaybeTimeoutClaimableHTLC {
                amount_satoshis, ..
            }
            | LightningBalance::MaybePreimageClaimableHTLC {
                amount_satoshis, ..
            }
            | LightningBalance::CounterpartyRevokedOutputClaimable {
                amount_satoshis, ..
            } => {
                contested += u128::from(*amount_satoshis);
            }
        }
    }
    for sweep in &balances.pending_balances_from_channel_closures {
        let amount = match sweep {
            PendingSweepBalance::PendingBroadcast {
                amount_satoshis, ..
            }
            | PendingSweepBalance::BroadcastAwaitingConfirmation {
                amount_satoshis, ..
            }
            | PendingSweepBalance::AwaitingThresholdConfirmations {
                amount_satoshis, ..
            } => *amount_satoshis,
        };
        closing += u128::from(amount);
    }

    WalletBalanceBreakdown {
        onchain_spendable_sats: Some(balances.spendable_onchain_balance_sats),
        onchain_total_sats: Some(balances.total_onchain_balance_sats),
        anchor_reserve_sats: Some(balances.total_anchor_channels_reserve_sats),
        lightning_spendable_sats: u64::try_from(outbound_msat / 1000).ok(),
        closing_sats: u64::try_from(closing).ok(),
        contested_sats: u64::try_from(contested).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::PublicKey;
    use ldk_node::lightning::chain::channelmonitor::BalanceSource;
    use ldk_node::lightning::types::payment::{PaymentHash, PaymentPreimage};
    use ldk_node::{LightningBalance, PendingSweepBalance};
    use std::str::FromStr;

    fn balances() -> BalanceDetails {
        BalanceDetails {
            total_onchain_balance_sats: 100_000,
            spendable_onchain_balance_sats: 70_000,
            total_anchor_channels_reserve_sats: 20_000,
            total_lightning_balance_sats: 900_000,
            lightning_balances: vec![],
            pending_balances_from_channel_closures: vec![],
        }
    }

    fn counterparty() -> PublicKey {
        PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
    }

    fn on_close() -> LightningBalance {
        LightningBalance::ClaimableOnChannelClose {
            channel_id: ChannelId([1; 32]),
            counterparty_node_id: counterparty(),
            amount_satoshis: 123,
            transaction_fee_satoshis: 10,
            outbound_payment_htlc_rounded_msat: 0,
            outbound_forwarded_htlc_rounded_msat: 0,
            inbound_claiming_htlc_rounded_msat: 0,
            inbound_htlc_rounded_msat: 0,
        }
    }

    #[test]
    fn funding_status_requires_explicit_evidence() {
        assert!(decode_funding_status(200, br#"{"confirmed":true}"#).unwrap());
        assert!(!decode_funding_status(200, br#"{"confirmed":false}"#).unwrap());
        assert!(!decode_funding_status(404, b"not found").unwrap());
        for (status, body) in [(500, b"{}".as_slice()), (200, b"{}"), (200, b"invalid")] {
            assert!(decode_funding_status(status, body).is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn funding_verification_errors_and_timeouts_do_not_erase_claims() {
        let mut balances = balances();
        balances.lightning_balances = vec![on_close()];
        balances.total_lightning_balance_sats = 123;
        let open = HashSet::new();
        assert!(verify_closed_funding(&mut balances, &open, |_| async {
            Err(LightningError::Backend("missing monitor or unavailable history".into()))
        }).await.is_err());
        assert_eq!(balances.total_lightning_balance_sats, 123);
        assert!(verify_closed_funding(&mut balances, &open, |_| {
            std::future::pending::<Result<bool, LightningError>>()
        }).await.is_err());
        assert_eq!(balances.total_lightning_balance_sats, 123);
        assert_eq!(balances.lightning_balances.len(), 1);
    }

    #[tokio::test]
    async fn funding_verification_keeps_confirmed_and_skips_open_channels() {
        let mut balances = balances();
        let mut confirmed = on_close();
        if let LightningBalance::ClaimableOnChannelClose { channel_id, .. } = &mut confirmed {
            *channel_id = ChannelId([2; 32]);
        }
        balances.lightning_balances = vec![on_close(), confirmed];
        balances.total_lightning_balance_sats = 246;
        verify_closed_funding(&mut balances, &HashSet::new(), |id| async move {
            Ok(id == ChannelId([2; 32]))
        }).await.unwrap();
        assert_eq!(balances.total_lightning_balance_sats, 123);
        assert_eq!(breakdown(&balances, []).closing_sats, Some(123));
        verify_closed_funding(&mut balances, &HashSet::from([ChannelId([2; 32])]), |_| async {
            panic!("open channels must not trigger funding queries")
        }).await.unwrap();
    }

    #[test]
    fn ghost_channel_is_excluded_from_closing_and_aggregate() {
        let mut balances = balances();
        let mut ghost = on_close();
        if let LightningBalance::ClaimableOnChannelClose { amount_satoshis, .. } = &mut ghost {
            *amount_satoshis = 79_638;
        }
        balances.lightning_balances = vec![ghost];
        balances.total_lightning_balance_sats = 79_638;
        filter_unfunded_closures(&mut balances, &HashSet::new(), &HashSet::new());
        assert_eq!(breakdown(&balances, []).closing_sats, Some(0));
        assert_eq!(balances.total_lightning_balance_sats, 0);
        assert_eq!(balances.total_onchain_balance_sats, 100_000);
    }

    #[test]
    fn confirmed_funding_and_open_channels_keep_their_claims() {
        for open in [false, true] {
            let mut balances = balances();
            balances.lightning_balances = vec![on_close()];
            balances.total_lightning_balance_sats = 123;
            let ids = HashSet::from([ChannelId([1; 32])]);
            let empty = HashSet::new();
            filter_unfunded_closures(&mut balances,
                if open { &ids } else { &empty }, if open { &empty } else { &ids });
            assert_eq!(balances.total_lightning_balance_sats, 123);
            assert_eq!(balances.lightning_balances.len(), 1);
        }
    }

    #[test]
    fn onchain_categories_and_usable_outbound_capacity_are_independent_of_total_claims() {
        let result = breakdown(
            &balances(),
            [
                (ChannelId([1; 32]), true, 12_600),
                (ChannelId([2; 32]), true, 4_600),
                (ChannelId([3; 32]), false, 999_000),
            ],
        );
        assert_eq!(
            result,
            WalletBalanceBreakdown {
                onchain_spendable_sats: Some(70_000),
                onchain_total_sats: Some(100_000),
                anchor_reserve_sats: Some(20_000),
                lightning_spendable_sats: Some(17),
                closing_sats: Some(0),
                contested_sats: Some(0),
            }
        );
    }

    #[test]
    fn open_channel_claim_is_not_closing_even_when_peer_is_offline() {
        let mut balances = balances();
        balances.lightning_balances = vec![on_close()];
        for usable in [true, false] {
            let result = breakdown(&balances, [(ChannelId([1; 32]), usable, 10_000)]);
            assert_eq!(result.closing_sats, Some(0));
            assert_eq!(result.contested_sats, Some(0));
        }
    }

    #[test]
    fn force_closed_channel_claim_before_confirmation_is_closing() {
        let mut balances = balances();
        balances.lightning_balances = vec![on_close()];
        let result = breakdown(&balances, []);
        assert_eq!(result.closing_sats, Some(123));
        assert_eq!(result.contested_sats, Some(0));
        assert_eq!(result.lightning_spendable_sats, Some(0));
    }

    #[test]
    fn each_lightning_claim_maps_to_exactly_one_bucket() {
        let channel_id = ChannelId([1; 32]);
        let counterparty_node_id = counterparty();
        let amount_satoshis = 123;
        let payment_hash = PaymentHash([2; 32]);
        let claims = [
            (
                LightningBalance::ClaimableAwaitingConfirmations {
                    channel_id,
                    counterparty_node_id,
                    amount_satoshis,
                    confirmation_height: 150,
                    source: BalanceSource::CounterpartyForceClosed,
                },
                123,
                0,
            ),
            (
                LightningBalance::ContentiousClaimable {
                    channel_id,
                    counterparty_node_id,
                    amount_satoshis,
                    timeout_height: 150,
                    payment_hash,
                    payment_preimage: PaymentPreimage([3; 32]),
                },
                0,
                123,
            ),
            (
                LightningBalance::MaybeTimeoutClaimableHTLC {
                    channel_id,
                    counterparty_node_id,
                    amount_satoshis,
                    claimable_height: 150,
                    payment_hash,
                    outbound_payment: true,
                },
                0,
                123,
            ),
            (
                LightningBalance::MaybePreimageClaimableHTLC {
                    channel_id,
                    counterparty_node_id,
                    amount_satoshis,
                    expiry_height: 150,
                    payment_hash,
                },
                0,
                123,
            ),
            (
                LightningBalance::CounterpartyRevokedOutputClaimable {
                    channel_id,
                    counterparty_node_id,
                    amount_satoshis,
                },
                0,
                123,
            ),
        ];
        for (claim, closing, contested) in claims {
            let mut balances = balances();
            balances.lightning_balances = vec![claim];
            let result = breakdown(&balances, []);
            assert_eq!(
                result.closing_sats,
                Some(closing),
                "{:?}",
                balances.lightning_balances
            );
            assert_eq!(result.contested_sats, Some(contested));
            assert_eq!(result.lightning_spendable_sats, Some(0));
        }
    }

    #[test]
    fn every_pending_sweep_variant_is_closing_including_unknown_channel() {
        let sweeps = [
            PendingSweepBalance::PendingBroadcast {
                channel_id: None,
                amount_satoshis: 11,
            },
            PendingSweepBalance::BroadcastAwaitingConfirmation {
                channel_id: Some(ChannelId([1; 32])),
                amount_satoshis: 22,
                latest_broadcast_height: 100,
                latest_spending_txid: bitcoin::Txid::all_zeros(),
            },
            PendingSweepBalance::AwaitingThresholdConfirmations {
                channel_id: Some(ChannelId([1; 32])),
                amount_satoshis: 33,
                latest_spending_txid: bitcoin::Txid::all_zeros(),
                confirmation_hash: bitcoin::BlockHash::all_zeros(),
                confirmation_height: 101,
            },
        ];
        for (sweep, expected) in sweeps.iter().zip([11, 22, 33]) {
            let mut balances = balances();
            balances.pending_balances_from_channel_closures = vec![sweep.clone()];
            let result = breakdown(&balances, []);
            assert_eq!(result.closing_sats, Some(expected));
            assert_eq!(result.contested_sats, Some(0));
            assert_eq!(result.onchain_total_sats, Some(100_000));
        }
        let mut balances = balances();
        balances.lightning_balances = vec![on_close()];
        balances.pending_balances_from_channel_closures = sweeps.to_vec();
        assert_eq!(breakdown(&balances, []).closing_sats, Some(189));
    }
}
