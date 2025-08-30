use cosmwasm_std::{Addr, Env, StdResult, Storage, Timestamp};

use crate::errors::ContractError;
use crate::states::{CONFIG, RATE_LIMITS, SECURITY_EVENTS};
use crate::types::{RateLimit, SecurityEvent, SecurityEventType, SecuritySeverity};

pub fn check_rate_limit(
    storage: &mut dyn Storage,
    env: &Env,
    user: &Addr,
) -> Result<(), ContractError> {
    let config = CONFIG.load(storage)?;
    let day = env.block.time.seconds() / 86400;
    let key = (user, day);

    let mut rate_limit = RATE_LIMITS.may_load(storage, key)?.unwrap_or(RateLimit {
        user: user.clone(),
        day,
        count: 0,
    });

    if rate_limit.count >= config.rate_limit_per_user {
        // Log security event
        let event = SecurityEvent {
            event_type: SecurityEventType::RateLimitExceeded,
            timestamp: env.block.time,
            actor: user.clone(),
            details: format!("User exceeded rate limit of {}", config.rate_limit_per_user),
            severity: SecuritySeverity::Medium,
        };
        SECURITY_EVENTS.save(
            storage,
            (env.block.time.seconds(), &format!("rate_limit_{}", user)),
            &event,
        )?;

        return Err(ContractError::RateLimitExceeded {});
    }

    rate_limit.count += 1;
    RATE_LIMITS.save(storage, key, &rate_limit)?;

    Ok(())
}

pub fn log_security_event(
    storage: &mut dyn Storage,
    timestamp: Timestamp,
    actor: &Addr,
    event_type: SecurityEventType,
    details: String,
    severity: SecuritySeverity,
) -> StdResult<()> {
    let event = SecurityEvent {
        event_type: event_type.clone(),
        timestamp,
        actor: actor.clone(),
        details,
        severity,
    };
    SECURITY_EVENTS.save(
        storage,
        (
            timestamp.seconds(),
            &format!("security_{:?}_{}", event_type, timestamp.nanos()),
        ),
        &event,
    )
}
