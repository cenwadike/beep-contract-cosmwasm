use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Contract is paused")]
    ContractPaused {},

    #[error("Circuit breaker triggered: {reason}")]
    CircuitBreakerTriggered { reason: String },

    #[error("Address is blacklisted: {address}")]
    Blacklisted { address: String },

    #[error("Rate limit exceeded")]
    RateLimitExceeded {},

    #[error("Intent not found: {id}")]
    IntentNotFound { id: String },

    #[error("Intent already exists: {id}")]
    IntentAlreadyExists { id: String },

    #[error("Invalid intent status")]
    InvalidIntentStatus {},

    #[error("Insufficient funds")]
    InsufficientFunds {},

    #[error("Nonce mismatch")]
    NonceMismatch {},

    #[error("Operation not supported")]
    OperationNotSupported {},

    #[error("Config proposal not found: {id}")]
    ConfigProposalNotFound { id: u64 },

    #[error("Config proposal expired: {id}")]
    ConfigProposalExpired { id: u64 },

    #[error("Already approved by guardian")]
    AlreadyApproved {},

    #[error("Unsupported token")]
    UnsupportedToken {},

    #[error("Unimplemented")]
    Unimplemented {},
}
