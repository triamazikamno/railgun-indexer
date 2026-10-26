use crate::store::{Store, StoreError};

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
    pub const fn v4_manifest_sequence(self) -> u64 {
        self.sequence
    }
}
