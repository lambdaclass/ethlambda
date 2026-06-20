#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage error:{0}")]
    Storage(#[from] crate::api::Error),
}
