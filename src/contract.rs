use cosmwasm_std::{
    Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint128, entry_point,
};
use cw2::set_contract_version;

use crate::errors::ContractError;
use crate::execute::{
    execute_add_ibc_connection, execute_add_supported_protocols, execute_add_supported_tokens,
    execute_approve_config_proposal, execute_approve_recovery, execute_approve_user_recovery,
    execute_cancel_intent, execute_create_intent, execute_deposit_to_wallet,
    execute_execute_config_proposal, execute_fill_intent, execute_initiate_recovery,
    execute_initiate_user_recovery, execute_paymaster_fund, execute_propose_config_update,
    execute_remove_ibc_connection, execute_remove_supported_protocols,
    execute_remove_supported_tokens, execute_reset_circuit_breaker, execute_transfer_from_wallet,
    execute_trigger_circuit_breaker, execute_update_admin, execute_update_default_timeout_height,
    execute_update_ibc_connection,
};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::validations::*;
use crate::{query, types::*};
use crate::{security, states::*, utils};

// Contract metadata
const CONTRACT_NAME: &str = "crates.io:beep-contract";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // Validate input parameters
    validate_instantiate_msg(&msg)?;

    // Validate and convert owners
    let owners: Vec<Addr> = msg
        .owners
        .into_iter()
        .map(|o| {
            deps.api
                .addr_validate(&o)
                .map_err(|_| ContractError::ValidationError("Invalid owner address".to_string()))
        })
        .collect::<Result<Vec<_>, ContractError>>()?;

    // Validate and convert guardians
    let guardians: Vec<Addr> = msg
        .guardians
        .into_iter()
        .map(|g| {
            deps.api
                .addr_validate(&g)
                .map_err(|_| ContractError::ValidationError("Invalid guardian address".to_string()))
        })
        .collect::<Result<Vec<_>, ContractError>>()?;

    // Enhanced validation
    if owners.is_empty() {
        return Err(ContractError::ValidationError(
            "At least one owner required".to_string(),
        ));
    }
    if msg.threshold == 0 || (msg.threshold as usize) > owners.len() {
        return Err(ContractError::ValidationError(
            "Invalid threshold configuration".to_string(),
        ));
    }
    if msg.threshold as usize > owners.len() / 2 + 3 {
        return Err(ContractError::ValidationError(
            "Threshold too high for security".to_string(),
        ));
    }

    let mut unique_owners = owners.clone();
    unique_owners.sort();
    unique_owners.dedup();
    if unique_owners.len() != owners.len() {
        return Err(ContractError::ValidationError(
            "Duplicate owners not allowed".to_string(),
        ));
    }

    let mut unique_guardians = guardians.clone();
    unique_guardians.sort();
    unique_guardians.dedup();
    if unique_guardians.len() != guardians.len() {
        return Err(ContractError::ValidationError(
            "Duplicate guardians not allowed".to_string(),
        ));
    }

    if owners.iter().any(|o| guardians.contains(o)) {
        return Err(ContractError::ValidationError(
            "Owners and guardians must be distinct".to_string(),
        ));
    }

    if msg.supported_tokens.is_empty() {
        return Err(ContractError::ValidationError(
            "At least one supported token required".to_string(),
        ));
    }
    if msg.supported_protocols.is_empty() {
        return Err(ContractError::ValidationError(
            "At least one supported protocol required".to_string(),
        ));
    }

    // Initialize configuration with immutable admin and fee_collector
    let config = Config {
        admin: info.sender.clone(),
        supported_tokens: msg.supported_tokens,
        supported_protocols: msg.supported_protocols,
        default_timeout_height: msg.default_timeout_height,
        fee_collector: info.sender.clone(),
        max_intent_duration: 86400 * 7,
        min_intent_amount: Uint128::from(1000u128),
        emergency_pause: false,
        rate_limit_per_user: 100,
    };

    // Set contract version
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    // Save initial state
    CONFIG.save(deps.storage, &config)?;
    OWNERS.save(deps.storage, &owners)?;
    THRESHOLD.save(deps.storage, &msg.threshold)?;
    NONCE.save(deps.storage, &0)?;
    GUARDIANS.save(deps.storage, &guardians)?;

    // Initialize recovery settings
    let recovery = Recovery {
        proposed_owner: None,
        initiated_at: None,
        guardian_approvals: vec![],
        threshold: std::cmp::max(1, guardians.len() as u32 / 2 + 1),
        delay: 48 * 3600,
    };
    RECOVERY.save(deps.storage, &recovery)?;

    // Initialize circuit breaker
    CIRCUIT_BREAKER.save(
        deps.storage,
        &CircuitBreakerState {
            is_triggered: false,
            trigger_reason: None,
            triggered_at: None,
            triggered_by: None,
            reset_approvals: vec![],
            reset_threshold: guardians.len() as u32 / 2 + 1,
        },
    )?;

    // Initialize fee structure
    FEE_STRUCTURE.save(
        deps.storage,
        &FeeStructure {
            base_fee: Uint128::zero(),
            percentage_fee: 50, // 0.5%
            gas_price: Uint128::from(1000u128),
            priority_multiplier: vec![
                (Priority::Low, 100),
                (Priority::Normal, 150),
                (Priority::High, 200),
                (Priority::Urgent, 300),
            ],
        },
    )?;

    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("admin", info.sender.to_string())
        .add_attribute("owners_count", owners.len().to_string())
        .add_attribute("threshold", msg.threshold.to_string())
        .add_attribute("contract_version", CONTRACT_VERSION))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    // Check circuit breaker
    let circuit_breaker = CIRCUIT_BREAKER.load(deps.storage)?;
    if circuit_breaker.is_triggered && !is_admin_or_guardian(deps.as_ref(), &info.sender)? {
        return Err(ContractError::CircuitBreakerTriggered {
            reason: circuit_breaker.trigger_reason.unwrap_or_default(),
        });
    }

    // Check emergency pause
    let config = CONFIG.load(deps.storage)?;
    if config.emergency_pause && !is_admin_or_guardian(deps.as_ref(), &info.sender)? {
        return Err(ContractError::ContractPaused {});
    }

    // Check blacklist
    if BLACKLISTED_ADDRESSES.has(deps.storage, &info.sender) {
        return Err(ContractError::Blacklisted {
            address: info.sender.to_string(),
        });
    }

    // Rate limiting check
    security::check_rate_limit(deps.storage, &env, &info.sender)?;

    // Increment nonce
    utils::increment_user_nonce(deps.storage, &info.sender, &env)?;

    // Delegate to execute module
    match msg {
        ExecuteMsg::CreateIntent {
            intent_id,
            input_tokens,
            intent_type,
            target_chain_id,
            timeout,
            tip,
            max_slippage,
            partial_fill_allowed,
            priority,
            use_wallet_balance,
        } => execute_create_intent(
            deps,
            env,
            info,
            intent_id,
            input_tokens,
            intent_type,
            target_chain_id,
            timeout,
            tip,
            max_slippage,
            partial_fill_allowed,
            priority,
            use_wallet_balance,
        ),
        ExecuteMsg::FillIntent {
            intent_id,
            source_chain_id,
            intent_type,
            use_wallet_balance,
        } => execute_fill_intent(
            deps,
            env,
            info,
            intent_id,
            source_chain_id,
            intent_type,
            use_wallet_balance,
        ),
        ExecuteMsg::CancelIntent { intent_id } => execute_cancel_intent(deps, env, info, intent_id),
        ExecuteMsg::UpdateAdmin { new_admin } => execute_update_admin(deps, info, new_admin),
        ExecuteMsg::AddSupportedTokens { tokens } => {
            execute_add_supported_tokens(deps, info, tokens)
        }
        ExecuteMsg::RemoveSupportedTokens { tokens } => {
            execute_remove_supported_tokens(deps, info, tokens)
        }
        ExecuteMsg::AddSupportedProtocols { protocols } => {
            execute_add_supported_protocols(deps, info, protocols)
        }
        ExecuteMsg::RemoveSupportedProtocols { protocols } => {
            execute_remove_supported_protocols(deps, info, protocols)
        }
        ExecuteMsg::UpdateDefaultTimeoutHeight {
            default_timeout_height,
        } => execute_update_default_timeout_height(deps, info, default_timeout_height),
        ExecuteMsg::AddIbcConnection {
            chain_id,
            port,
            channel_id,
        } => execute_add_ibc_connection(deps, info, env, chain_id, port, channel_id),
        ExecuteMsg::UpdateIbcConnection {
            chain_id,
            port,
            channel_id,
            is_active,
        } => execute_update_ibc_connection(deps, info, env, chain_id, port, channel_id, is_active),
        ExecuteMsg::RemoveIbcConnection { chain_id } => {
            execute_remove_ibc_connection(deps, info, chain_id)
        }
        ExecuteMsg::ProposeConfigUpdate {
            proposal_id,
            threshold,
            supported_tokens,
            supported_protocols,
            default_timeout_height,
        } => execute_propose_config_update(
            deps,
            env,
            info,
            proposal_id,
            threshold,
            supported_tokens,
            supported_protocols,
            default_timeout_height,
        ),
        ExecuteMsg::ApproveConfigProposal { proposal_id } => {
            execute_approve_config_proposal(deps, env, info, proposal_id)
        }
        ExecuteMsg::ExecuteConfigProposal { proposal_id } => {
            execute_execute_config_proposal(deps, env, info, proposal_id)
        }
        ExecuteMsg::InitiateRecovery { proposed_owner } => {
            execute_initiate_recovery(deps, env, info, proposed_owner)
        }
        ExecuteMsg::ApproveRecovery {} => execute_approve_recovery(deps, env, info),
        ExecuteMsg::InitiateUserRecovery { user, new_address } => {
            execute_initiate_user_recovery(deps, env, info, user, new_address)
        }
        ExecuteMsg::ApproveUserRecovery { user } => {
            execute_approve_user_recovery(deps, env, info, user)
        }
        ExecuteMsg::TriggerCircuitBreaker { reason } => {
            execute_trigger_circuit_breaker(deps, env, info, reason)
        }
        ExecuteMsg::ResetCircuitBreaker {} => execute_reset_circuit_breaker(deps, env, info),
        ExecuteMsg::DepositToWallet { tokens } => {
            execute_deposit_to_wallet(deps, env, info, tokens)
        }
        ExecuteMsg::TransferFromWallet { recipient, tokens } => {
            execute_transfer_from_wallet(deps, env, info, recipient, tokens)
        }
        ExecuteMsg::PaymasterFund { tokens } => execute_paymaster_fund(deps, env, info, tokens),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    query::handle_query(deps, env, msg)
}

fn is_admin_or_guardian(deps: Deps, sender: &Addr) -> Result<bool, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let guardians = GUARDIANS.load(deps.storage)?;
    Ok(sender == config.admin || guardians.contains(sender))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::coins;
    use cosmwasm_std::testing::*;

    #[test]
    #[allow(deprecated)]
    fn test_instantiate() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&Addr::unchecked("admin_user"), &coins(5000, "uatom"));

        // Use the mock's built-in address generation which respects the bech32_prefix
        let owner1 = deps.api.addr_make("owner1");
        let owner2 = deps.api.addr_make("owner2");
        let guardian1 = deps.api.addr_make("guardian1");

        // Valid instantiate message with generated addresses
        let msg = InstantiateMsg {
            supported_tokens: vec!["uatom".to_string(), "ujuno".to_string()],
            supported_protocols: vec!["juno".to_string(), "cosmoshub".to_string()],
            default_timeout_height: 1500,
            owners: vec![owner1.to_string(), owner2.to_string()],
            threshold: 2,
            guardians: vec![guardian1.to_string()],
        };

        // Should succeed
        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "action")
                .unwrap()
                .value,
            "instantiate"
        );
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "admin")
                .unwrap()
                .value,
            "admin_user"
        );
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "owners_count")
                .unwrap()
                .value,
            "2"
        );
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "threshold")
                .unwrap()
                .value,
            "2"
        );
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "contract_version")
                .unwrap()
                .value,
            CONTRACT_VERSION
        );

        // Invalid: empty owners
        let mut msg_invalid = msg.clone();
        msg_invalid.owners = vec![];
        let err = instantiate(deps.as_mut(), env.clone(), info.clone(), msg_invalid).unwrap_err();
        assert!(matches!(err, ContractError::ValidationError(_)));

        // Invalid: duplicate owners
        let mut msg_invalid = msg.clone();
        msg_invalid.owners = vec![owner1.to_string(), owner1.to_string()];
        let err = instantiate(deps.as_mut(), env.clone(), info.clone(), msg_invalid).unwrap_err();
        assert!(matches!(err, ContractError::ValidationError(_)));

        // Invalid: threshold too high
        let mut msg_invalid = msg.clone();
        msg_invalid.threshold = 10;
        let err = instantiate(deps.as_mut(), env.clone(), info.clone(), msg_invalid).unwrap_err();
        assert!(matches!(err, ContractError::ValidationError(_)));

        // Invalid: owners and guardians overlap
        let mut msg_invalid = msg.clone();
        msg_invalid.guardians = vec![owner1.to_string()];
        let err = instantiate(deps.as_mut(), env.clone(), info.clone(), msg_invalid).unwrap_err();
        assert!(matches!(err, ContractError::ValidationError(_)));

        // Invalid: empty supported tokens
        let mut msg_invalid = msg.clone();
        msg_invalid.supported_tokens = vec![];
        let err = instantiate(deps.as_mut(), env.clone(), info.clone(), msg_invalid).unwrap_err();
        assert!(matches!(err, ContractError::ValidationError(_)));

        // Invalid: empty supported protocols
        let mut msg_invalid = msg.clone();
        msg_invalid.supported_protocols = vec![];
        let err = instantiate(deps.as_mut(), env.clone(), info.clone(), msg_invalid).unwrap_err();
        assert!(matches!(err, ContractError::ValidationError(_)));

        // Invalid: duplicate guardians
        let mut msg_invalid = msg.clone();
        msg_invalid.guardians = vec![guardian1.to_string(), guardian1.to_string()];
        let err = instantiate(deps.as_mut(), env, info, msg_invalid).unwrap_err();
        assert!(matches!(err, ContractError::ValidationError(_)));
    }
}
