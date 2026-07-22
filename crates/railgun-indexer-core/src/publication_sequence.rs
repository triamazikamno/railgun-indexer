use crate::store::{Store, StoreError};
use std::future::Future;

#[derive(Debug, Clone)]
pub struct PoiPublicationSequenceAllocator {
    store: Store,
}

impl PoiPublicationSequenceAllocator {
    #[must_use]
    pub const fn new(store: Store) -> Self {
        Self { store }
    }

    pub async fn reserve_cycle(
        &self,
        minimum_sequence: u64,
    ) -> Result<PoiPublicationSequenceLease, StoreError> {
        let sequence = self
            .store
            .reserve_poi_publication_sequence(minimum_sequence)
            .await?;
        Ok(PoiPublicationSequenceLease { sequence })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoiPublicationSequenceLease {
    sequence: u64,
}

impl PoiPublicationSequenceLease {
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn legacy_manifest_sequence(self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn v4_manifest_sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Debug)]
pub struct DualPoiPublicationOutcome<L, V> {
    pub legacy: L,
    pub v4: V,
}

pub async fn run_dual_poi_publication_cycle<Legacy, V4, LegacyFuture, V4Future, L, V>(
    lease: PoiPublicationSequenceLease,
    publish_legacy: Legacy,
    publish_v4: V4,
) -> DualPoiPublicationOutcome<L, V>
where
    Legacy: FnOnce(u64) -> LegacyFuture,
    V4: FnOnce(u64) -> V4Future,
    LegacyFuture: Future<Output = L>,
    V4Future: Future<Output = V>,
{
    let legacy = publish_legacy(lease.legacy_manifest_sequence());
    let v4 = publish_v4(lease.v4_manifest_sequence());
    let (legacy, v4) = futures_util::future::join(legacy, v4).await;
    DualPoiPublicationOutcome { legacy, v4 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn dual_cycle_assigns_one_sequence_to_both_channels() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let legacy_observed = Arc::clone(&observed);
        let v4_observed = Arc::clone(&observed);
        let lease = PoiPublicationSequenceLease { sequence: 42 };

        let outcome = run_dual_poi_publication_cycle(
            lease,
            move |sequence| async move {
                legacy_observed
                    .lock()
                    .expect("legacy observations lock")
                    .push(("legacy", sequence));
                Ok::<_, &'static str>(())
            },
            move |sequence| async move {
                v4_observed
                    .lock()
                    .expect("v4 observations lock")
                    .push(("v4", sequence));
                Ok::<_, &'static str>(())
            },
        )
        .await;

        let mut observed = observed.lock().expect("observations lock").clone();
        observed.sort_unstable();
        assert_eq!(observed, vec![("legacy", 42), ("v4", 42)]);
        assert!(outcome.legacy.is_ok());
        assert!(outcome.v4.is_ok());
    }

    #[tokio::test]
    async fn one_channel_failure_does_not_cancel_the_other_channel() {
        let lease = PoiPublicationSequenceLease { sequence: 43 };

        let outcome = run_dual_poi_publication_cycle(
            lease,
            |sequence| async move { Err::<(), _>(("legacy failed", sequence)) },
            |sequence| async move { Ok::<_, (&'static str, u64)>(sequence) },
        )
        .await;

        assert_eq!(outcome.legacy, Err(("legacy failed", 43)));
        assert_eq!(outcome.v4, Ok(43));
    }
}
