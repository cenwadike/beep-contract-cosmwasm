use cosmwasm_std::{Addr, Env, Storage};
use sha2::{Digest, Sha256};

use crate::errors::ContractError;
use crate::states::USER_NONCE;

pub fn increment_user_nonce(
    storage: &mut dyn Storage,
    user: &Addr,
    _env: &Env,
) -> Result<u128, ContractError> {
    let mut nonce = USER_NONCE.may_load(storage, user)?.unwrap_or_default();

    nonce = nonce
        .checked_add(1)
        .ok_or_else(|| ContractError::ValidationError("Nonce overflow".to_string()))?;

    USER_NONCE.save(storage, user, &nonce)?;

    Ok(nonce)
}

pub fn generate_intent_id(creator: &Addr, chain_id: &str, nonce: u128) -> String {
    let mut hasher = Sha256::new();
    hasher.update(creator.as_bytes());
    hasher.update(chain_id.as_bytes());
    hasher.update(nonce.to_be_bytes());
    format!("intent-{}", hex::encode(hasher.finalize()))
}
