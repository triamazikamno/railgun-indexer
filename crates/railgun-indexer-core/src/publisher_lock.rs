use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgAdvisoryLock, PgAdvisoryLockGuard};
use sqlx::{Either, PgPool, Postgres};
use thiserror::Error;

/// Held by the publisher for its lifetime and by offline tools that rewrite indexed rows.
pub const PUBLISHER_ADVISORY_LOCK_NAME: &str = "railgun-indexer/publication-owner/v1";

pub type PublisherLockGuard<'lock> = PgAdvisoryLockGuard<'lock, PoolConnection<Postgres>>;

#[derive(Debug, Error)]
pub enum PublisherLockError {
    #[error("acquire publisher lock connection")]
    Connection(#[source] sqlx::Error),
    #[error("try publisher advisory lock")]
    TryLock(#[source] sqlx::Error),
    #[error("publisher advisory lock is held; stop the publisher before running this process")]
    Held,
}

pub async fn try_acquire_publisher_lock<'lock>(
    lock: &'lock PgAdvisoryLock,
    pool: &PgPool,
) -> Result<PublisherLockGuard<'lock>, PublisherLockError> {
    let connection = pool
        .acquire()
        .await
        .map_err(PublisherLockError::Connection)?;
    match lock
        .try_acquire(connection)
        .await
        .map_err(PublisherLockError::TryLock)?
    {
        Either::Left(guard) => Ok(guard),
        Either::Right(_) => Err(PublisherLockError::Held),
    }
}
