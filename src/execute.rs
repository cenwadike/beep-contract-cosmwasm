use cosmwasm_std::{
    Addr, BankMsg, Coin, CosmosMsg, DepsMut, Env, IbcMsg, IbcTimeout, MessageInfo, Response,
    StdResult, Uint128, WasmMsg, to_json_binary,
};
use cw20::Cw20ExecuteMsg;

use crate::errors::ContractError;
use crate::msg::IbcExecuteMsg;
use crate::states::{
    BLACKLISTED_ADDRESSES, CIRCUIT_BREAKER, CONFIG, CONFIG_PROPOSALS, ESCROW, FEE_STRUCTURE,
    GUARDIANS, HEALTH_STATUS, IBC_CONNECTIONS, INTENTS, OWNERS, PAYMASTER_RESERVE, RATE_LIMITS,
    RECOVERY, THRESHOLD, USER_NONCE, USER_RECOVERIES, WALLET_BALANCES,
};
use crate::types::{
    BeepCoin, Config, ConfigProposal, Connection, FeeStructure, Intent, IntentStatus, IntentType,
    PaymasterReserve, Priority, RateLimit, UpdateConfig, UserRecovery, WalletBalance,
};
use crate::validations::{validate_filling, validate_intent_type, validate_tokens};

pub fn execute_create_intent(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    intent_id: String,
    input_tokens: Vec<BeepCoin>,
    intent_type: IntentType,
    target_chain_id: String,
    timeout: Option<u64>,
    tip: BeepCoin,
    max_slippage: Option<u64>,
    partial_fill_allowed: bool,
    priority: Priority,
    use_wallet_balance: bool,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let nonce = USER_NONCE
        .may_load(deps.storage, &info.sender)?
        .unwrap_or(0);
    let mut paymaster_reserve = PAYMASTER_RESERVE.load(deps.storage)?;
    let fee_structure = FEE_STRUCTURE.load(deps.storage)?;
    let gas_price = calculate_gas_price(&fee_structure, &priority);
    let max_gas = Uint128::from(1_000_000u128); // Cap gas per transaction

    if !INTENTS.may_load(deps.storage, &intent_id)?.is_none() {
        return Err(ContractError::ValidationError(
            "Intent ID already exists".to_string(),
        ));
    }

    validate_intent_type(&intent_type, &config)?;
    let mut messages = vec![];

    // Gas payment: Try wallet balance, then transaction funds, then paymaster
    let gas_paid = deduct_gas_payment(
        deps.storage,
        &env,
        &info,
        &mut paymaster_reserve,
        &config,
        gas_price,
        max_gas,
        use_wallet_balance,
    )?;
    messages.extend(gas_paid.messages);
    PAYMASTER_RESERVE.save(deps.storage, &paymaster_reserve)?;

    if use_wallet_balance {
        let mut wallet_balance = WALLET_BALANCES
            .may_load(deps.storage, &info.sender)?
            .unwrap_or(WalletBalance {
                address: info.sender.clone(),
                balances: vec![],
            });

        for token in input_tokens.iter() {
            let existing_balance = wallet_balance
                .balances
                .iter_mut()
                .find(|b| b.token == token.token);
            match existing_balance {
                Some(balance) => {
                    if balance.amount < token.amount {
                        return Err(ContractError::ValidationError(format!(
                            "Insufficient wallet balance for token {}",
                            token.token
                        )));
                    }
                    balance.amount -= token.amount;
                }
                None => {
                    return Err(ContractError::ValidationError(format!(
                        "Token {} not found in wallet",
                        token.token
                    )));
                }
            }
        }
        let tip_balance = wallet_balance
            .balances
            .iter_mut()
            .find(|b| b.token == tip.token);
        match tip_balance {
            Some(balance) => {
                if balance.amount < tip.amount {
                    return Err(ContractError::ValidationError(format!(
                        "Insufficient wallet balance for tip token {}",
                        tip.token
                    )));
                }
                balance.amount -= tip.amount;
            }
            None => {
                return Err(ContractError::ValidationError(format!(
                    "Tip token {} not found in wallet",
                    tip.token
                )));
            }
        }
        WALLET_BALANCES.save(deps.storage, &info.sender, &wallet_balance)?;
    } else {
        let mut input_and_tip = input_tokens.clone();
        input_and_tip.push(tip.clone());
        let validate_input_and_tip = validate_tokens(&deps, &env, &info, &input_and_tip)?;
        messages = [messages, validate_input_and_tip].concat();
    }

    let intent = Intent {
        id: intent_id.clone(),
        creator: info.sender.clone(),
        input_tokens: input_tokens.clone(),
        intent_type,
        origin_chain_id: env.block.chain_id.clone(),
        target_chain_id,
        status: IntentStatus::Active,
        executor: None,
        created_at: env.block.height,
        timeout: timeout.unwrap_or(env.block.height + config.default_timeout_height),
        tip,
        max_slippage,
        partial_fill_allowed,
        priority,
        filled_amount: Uint128::zero(),
        execution_fee: Uint128::zero(),
        retry_count: 0,
    };

    INTENTS.save(deps.storage, &intent_id, &intent)?;
    ESCROW.save(deps.storage, (&info.sender, &intent_id), &input_tokens)?;
    USER_NONCE.save(deps.storage, &info.sender, &(nonce + 1))?;

    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_messages(messages)
        .add_attribute("action", "create_intent")
        .add_attribute("intent_id", intent_id)
        .add_attribute("status", "active")
        .add_attribute("use_wallet_balance", use_wallet_balance.to_string()))
}

pub fn execute_fill_intent(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    intent_id: String,
    source_chain_id: String,
    intent_type: IntentType,
    use_wallet_balance: bool,
) -> Result<Response, ContractError> {
    let mut intent = INTENTS.load(deps.storage, &intent_id)?;
    let config = CONFIG.load(deps.storage)?;
    let fee_structure = FEE_STRUCTURE.load(deps.storage)?;
    let mut paymaster_reserve = PAYMASTER_RESERVE.load(deps.storage)?;
    let gas_price = calculate_gas_price(&fee_structure, &intent.priority);
    let max_gas = Uint128::from(1_000_000u128);

    // Validate circuit breaker and blacklist
    let circuit_breaker = CIRCUIT_BREAKER.load(deps.storage)?;
    if circuit_breaker.is_triggered {
        return Err(ContractError::CircuitBreakerTriggered {
            reason: String::from("Maintenance"),
        });
    }
    if BLACKLISTED_ADDRESSES
        .may_load(deps.storage, &info.sender)
        .is_err()
    {
        return Err(ContractError::Blacklisted {
            address: info.sender.to_string(),
        });
    }

    if !intent.can_be_filled() {
        update_health_status(deps, &env, false, Some("Invalid intent status".to_string()))?;
        return Err(ContractError::InvalidIntentStatus {});
    }
    if source_chain_id != env.block.chain_id {
        update_health_status(
            deps,
            &env,
            false,
            Some("Source chain ID mismatch".to_string()),
        )?;
        return Err(ContractError::ValidationError(
            "Source chain ID does not match current chain".to_string(),
        ));
    }
    if intent.intent_type != intent_type {
        update_health_status(deps, &env, false, Some("Intent type mismatch".to_string()))?;
        return Err(ContractError::ValidationError(
            "Intent type mismatch".to_string(),
        ));
    }

    // Gas payment
    let gas_paid = deduct_gas_payment(
        deps.storage,
        &env,
        &info,
        &mut paymaster_reserve,
        &config,
        gas_price,
        max_gas,
        use_wallet_balance,
    )?;
    let mut messages = gas_paid.messages;
    PAYMASTER_RESERVE.save(deps.storage, &paymaster_reserve)?;

    // Validate and deduct output tokens
    let (tokens, fill_messages) = validate_filling(
        &mut deps,
        &env,
        &info,
        &intent_id,
        &intent_type,
        use_wallet_balance,
    )?;
    messages.extend(fill_messages);
    ESCROW.save(deps.storage, (&info.sender, &intent_id), &tokens)?;
    intent.executor = Some(info.sender.clone());
    INTENTS.save(deps.storage, &intent_id, &intent)?;

    if intent.origin_chain_id == intent.target_chain_id {
        if intent.origin_chain_id != env.block.chain_id {
            update_health_status(
                deps,
                &env,
                false,
                Some("Same-chain intent on wrong chain".to_string()),
            )?;
            return Err(ContractError::ValidationError(
                "Same-chain intent must be processed on origin chain".to_string(),
            ));
        }
        // Transfer input tokens and tip to executor
        for token in intent.input_tokens.iter() {
            if token.is_native {
                messages.push(add_native_transfer_msg(
                    &token.token,
                    &info.sender,
                    token.amount,
                )?);
            } else {
                messages.push(add_cw20_transfer_msg(
                    &token.token,
                    &info.sender,
                    token.amount,
                )?);
            }
        }
        if intent.tip.is_native {
            messages.push(add_native_transfer_msg(
                &intent.tip.token,
                &info.sender,
                intent.tip.amount,
            )?);
        } else {
            messages.push(add_cw20_transfer_msg(
                &intent.tip.token,
                &info.sender,
                intent.tip.amount,
            )?);
        }
        // Transfer output tokens to creator or target address
        match &intent.intent_type {
            IntentType::Swap { output_tokens } => {
                for token in output_tokens {
                    let recipient = token
                        .target_address
                        .clone()
                        .unwrap_or(intent.creator.clone());
                    if token.is_native {
                        messages.push(add_native_transfer_msg(
                            &token.token,
                            &recipient,
                            token.amount,
                        )?);
                    } else {
                        messages.push(add_cw20_transfer_msg(
                            &token.token,
                            &recipient,
                            token.amount,
                        )?);
                    }
                }

                intent.filled_amount = output_tokens
                    .iter()
                    .fold(Uint128::zero(), |acc, token| acc + token.amount);
            }
            IntentType::LiquidStake { .. }
            | IntentType::Lend { .. }
            | IntentType::Generic { .. } => {
                update_health_status(
                    deps,
                    &env,
                    false,
                    Some("Unimplemented intent type".to_string()),
                )?;
                return Err(ContractError::Unimplemented {});
            }
        }
        intent.status = IntentStatus::Completed;
        INTENTS.save(deps.storage, &intent_id, &intent)?;
        ESCROW.remove(deps.storage, (&intent.creator, &intent_id));
        ESCROW.remove(deps.storage, (&info.sender, &intent_id));
        update_health_status(deps, &env, true, None)?;
        Ok(Response::new()
            .add_messages(messages)
            .add_attribute("action", "fill_intent_same_chain")
            .add_attribute("intent_id", intent_id)
            .add_attribute("executor", info.sender.to_string())
            .add_attribute("use_wallet_balance", use_wallet_balance.to_string()))
    } else {
        let connection = IBC_CONNECTIONS.load(deps.storage, &intent.target_chain_id)?;
        let timeout = IbcTimeout::with_timestamp(env.block.time.plus_seconds(120));
        let ibc_msg = IbcMsg::SendPacket {
            channel_id: connection.channel_id,
            data: to_json_binary(&IbcExecuteMsg::FillIntent {
                intent_id: intent_id.clone(),
                executor: info.sender.clone(),
            })?,
            timeout,
        };
        messages.push(CosmosMsg::Ibc(ibc_msg));
        update_health_status(deps, &env, true, None)?;

        Ok(Response::new()
            .add_messages(messages)
            .add_attribute("action", "fill_intent_cross_chain")
            .add_attribute("intent_id", intent_id)
            .add_attribute("executor", info.sender.to_string())
            .add_attribute("target_chain_id", intent.target_chain_id)
            .add_attribute("use_wallet_balance", use_wallet_balance.to_string()))
    }
}

pub fn execute_cancel_intent(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    intent_id: String,
) -> Result<Response, ContractError> {
    let mut intent = INTENTS.load(deps.storage, &intent_id)?;
    let config = CONFIG.load(deps.storage)?;
    let fee_structure = FEE_STRUCTURE.load(deps.storage)?;
    let mut paymaster_reserve = PAYMASTER_RESERVE.load(deps.storage)?;
    let gas_price = calculate_gas_price(&fee_structure, &Priority::Normal);
    let max_gas = Uint128::from(1_000_000u128);

    if !intent.can_be_cancelled() {
        update_health_status(
            deps,
            &env,
            false,
            Some("Intent cannot be cancelled".to_string()),
        )?;
        return Err(ContractError::InvalidIntentStatus {});
    }
    if intent.creator != info.sender {
        update_health_status(deps, &env, false, Some("Unauthorized".to_string()))?;
        return Err(ContractError::Unauthorized {});
    }

    let gas_paid = deduct_gas_payment(
        deps.storage,
        &env,
        &info,
        &mut paymaster_reserve,
        &config,
        gas_price,
        max_gas,
        true,
    )?;
    let mut messages = gas_paid.messages;
    PAYMASTER_RESERVE.save(deps.storage, &paymaster_reserve)?;

    intent.status = IntentStatus::Cancelled;
    INTENTS.save(deps.storage, &intent_id, &intent)?;
    let tokens = ESCROW.load(deps.storage, (&info.sender, &intent_id))?;

    for token in tokens {
        if token.is_native {
            messages.push(add_native_transfer_msg(
                &token.token,
                &info.sender,
                token.amount,
            )?);
        } else {
            messages.push(add_cw20_transfer_msg(
                &token.token,
                &info.sender,
                token.amount,
            )?);
        }
    }
    ESCROW.remove(deps.storage, (&info.sender, &intent_id));
    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_messages(messages)
        .add_attribute("action", "cancel_intent")
        .add_attribute("intent_id", intent_id))
}

pub fn execute_deposit_to_wallet(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    tokens: Vec<BeepCoin>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let mut paymaster_reserve = PAYMASTER_RESERVE.load(deps.storage)?;
    let mut wallet_balance = WALLET_BALANCES
        .may_load(deps.storage, &info.sender)?
        .unwrap_or(WalletBalance {
            address: info.sender.clone(),
            balances: vec![],
        });
    let fee_structure = FEE_STRUCTURE.load(deps.storage)?;
    let gas_price = calculate_gas_price(&fee_structure, &Priority::Normal);
    let max_gas = Uint128::from(1_000_000u128);

    let gas_paid = deduct_gas_payment(
        deps.storage,
        &env,
        &info,
        &mut paymaster_reserve,
        &config,
        gas_price,
        max_gas,
        true,
    )?;
    let mut messages = gas_paid.messages;
    PAYMASTER_RESERVE.save(deps.storage, &paymaster_reserve)?;

    let validate_msgs = validate_tokens(&deps, &env, &info, &tokens)?;
    messages.extend(validate_msgs);
    let paymaster_fee_percentage = 50u32; // 0.5%

    for token in tokens {
        if !config.supported_tokens.contains(&token.token) {
            return Err(ContractError::UnsupportedToken {});
        }
        let paymaster_fee =
            token.amount * Uint128::from(paymaster_fee_percentage) / Uint128::from(10000u32);
        let deposit_amount = token.amount - paymaster_fee;

        let existing_balance = wallet_balance
            .balances
            .iter_mut()
            .find(|b| b.token == token.token);
        match existing_balance {
            Some(balance) => {
                balance.amount += deposit_amount;
            }
            None => {
                wallet_balance.balances.push(BeepCoin {
                    token: token.token.clone(),
                    amount: deposit_amount,
                    is_native: token.is_native,
                });
            }
        }

        let existing_reserve = paymaster_reserve
            .balances
            .iter_mut()
            .find(|b| b.token == token.token);
        match existing_reserve {
            Some(reserve) => {
                reserve.amount += paymaster_fee;
            }
            None => {
                paymaster_reserve.balances.push(BeepCoin {
                    token: token.token.clone(),
                    amount: paymaster_fee,
                    is_native: token.is_native,
                });
            }
        }
    }

    WALLET_BALANCES.save(deps.storage, &info.sender, &wallet_balance)?;
    PAYMASTER_RESERVE.save(deps.storage, &paymaster_reserve)?;
    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_messages(messages)
        .add_attribute("action", "deposit_to_wallet")
        .add_attribute("user", info.sender.to_string()))
}

pub fn execute_transfer_from_wallet(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    recipient: Addr,
    tokens: Vec<BeepCoin>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let mut wallet_balance = WALLET_BALANCES
        .may_load(deps.storage, &info.sender)?
        .unwrap_or(WalletBalance {
            address: info.sender.clone(),
            balances: vec![],
        });
    let mut paymaster_reserve = PAYMASTER_RESERVE.load(deps.storage)?;
    let fee_structure = FEE_STRUCTURE.load(deps.storage)?;
    let gas_price = calculate_gas_price(&fee_structure, &Priority::Normal);
    let max_gas = Uint128::from(1_000_000u128);

    let gas_paid = deduct_gas_payment(
        deps.storage,
        &env,
        &info,
        &mut paymaster_reserve,
        &config,
        gas_price,
        max_gas,
        true,
    )?;
    let mut messages = gas_paid.messages;
    PAYMASTER_RESERVE.save(deps.storage, &paymaster_reserve)?;

    for token in tokens.iter() {
        let existing_balance = wallet_balance
            .balances
            .iter_mut()
            .find(|b| b.token == token.token);
        match existing_balance {
            Some(balance) => {
                if balance.amount < token.amount {
                    return Err(ContractError::ValidationError(format!(
                        "Insufficient wallet balance for token {}",
                        token.token
                    )));
                }
                balance.amount -= token.amount;
            }
            None => {
                return Err(ContractError::ValidationError(format!(
                    "Token {} not found in wallet",
                    token.token
                )));
            }
        }
        if token.is_native {
            messages.push(add_native_transfer_msg(
                &token.token,
                &recipient,
                token.amount,
            )?);
        } else {
            messages.push(add_cw20_transfer_msg(
                &token.token,
                &recipient,
                token.amount,
            )?);
        }
    }

    WALLET_BALANCES.save(deps.storage, &info.sender, &wallet_balance)?;
    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_messages(messages)
        .add_attribute("action", "transfer_from_wallet")
        .add_attribute("recipient", recipient.to_string()))
}

pub fn execute_paymaster_fund(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    tokens: Vec<BeepCoin>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let mut paymaster_reserve = PAYMASTER_RESERVE.load(deps.storage)?;
    let fee_structure = FEE_STRUCTURE.load(deps.storage)?;
    let gas_price = calculate_gas_price(&fee_structure, &Priority::Normal);
    let max_gas = Uint128::from(1_000_000u128);

    let gas_paid = deduct_gas_payment(
        deps.storage,
        &env,
        &info,
        &mut paymaster_reserve,
        &config,
        gas_price,
        max_gas,
        true,
    )?;
    let mut messages = gas_paid.messages;
    PAYMASTER_RESERVE.save(deps.storage, &paymaster_reserve)?;

    let validate_msgs = validate_tokens(&deps, &env, &info, &tokens)?;
    messages.extend(validate_msgs);

    for token in tokens {
        if !config.supported_tokens.contains(&token.token) {
            return Err(ContractError::UnsupportedToken {});
        }
        let existing_reserve = paymaster_reserve
            .balances
            .iter_mut()
            .find(|b| b.token == token.token);
        match existing_reserve {
            Some(reserve) => {
                reserve.amount += token.amount;
            }
            None => {
                paymaster_reserve.balances.push(token);
            }
        }
    }

    PAYMASTER_RESERVE.save(deps.storage, &paymaster_reserve)?;
    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_messages(messages)
        .add_attribute("action", "paymaster_fund")
        .add_attribute("user", info.sender.to_string()))
}

pub fn execute_initiate_user_recovery(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    user: Addr,
    new_address: Addr,
) -> Result<Response, ContractError> {
    let guardians = GUARDIANS.load(deps.storage)?;
    if !guardians.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    let existing_recovery = USER_RECOVERIES.may_load(deps.storage, &user)?;
    if existing_recovery.is_some() {
        return Err(ContractError::ValidationError(
            "Recovery already in progress for user".to_string(),
        ));
    }
    let recovery = UserRecovery {
        user: user.clone(),
        new_address: Some(new_address.clone()),
        initiated_at: Some(env.block.time),
        guardian_approvals: vec![info.sender.clone()],
        threshold: guardians.len() as u32 / 2 + 1,
        delay: 48 * 3600,
    };
    USER_RECOVERIES.save(deps.storage, &user, &recovery)?;
    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_attribute("action", "initiate_user_recovery")
        .add_attribute("user", user.to_string())
        .add_attribute("new_address", new_address.to_string())
        .add_attribute("initiator", info.sender.to_string()))
}

pub fn execute_approve_user_recovery(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    user: Addr,
) -> Result<Response, ContractError> {
    let guardians = GUARDIANS.load(deps.storage)?;
    if !guardians.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    let mut recovery = USER_RECOVERIES.load(deps.storage, &user)?;
    if recovery.new_address.is_none() {
        return Err(ContractError::ValidationError(
            "No recovery proposal active for user".to_string(),
        ));
    }
    if recovery.guardian_approvals.contains(&info.sender) {
        return Err(ContractError::ValidationError(
            "Sender has already approved user recovery".to_string(),
        ));
    }
    recovery.guardian_approvals.push(info.sender.clone());
    if (recovery.guardian_approvals.len() as u32) >= recovery.threshold
        && env.block.time.seconds() >= recovery.initiated_at.unwrap().seconds() + recovery.delay
    {
        let wallet_balance =
            WALLET_BALANCES
                .may_load(deps.storage, &user)?
                .unwrap_or(WalletBalance {
                    address: user.clone(),
                    balances: vec![],
                });
        let new_address = recovery.new_address.take().unwrap();
        WALLET_BALANCES.save(deps.storage, &new_address, &wallet_balance)?;
        WALLET_BALANCES.remove(deps.storage, &user);
        recovery.initiated_at = None;
        recovery.guardian_approvals = vec![];
        USER_RECOVERIES.save(deps.storage, &user, &recovery)?;
    } else {
        USER_RECOVERIES.save(deps.storage, &user, &recovery)?;
    }
    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_attribute("action", "approve_user_recovery")
        .add_attribute("user", user.to_string())
        .add_attribute("approver", info.sender.to_string()))
}

pub fn execute_update_admin(
    deps: DepsMut,
    info: MessageInfo,
    new_admin: Addr,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    let owners = OWNERS.load(deps.storage)?;
    if !owners.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    config.admin = new_admin.clone();
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "update_admin")
        .add_attribute("old_admin", info.sender.to_string())
        .add_attribute("new_admin", new_admin.to_string()))
}

pub fn execute_add_supported_tokens(
    deps: DepsMut,
    info: MessageInfo,
    tokens: Vec<String>,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    let owners = OWNERS.load(deps.storage)?;
    if !owners.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    for token in tokens {
        if !config.supported_tokens.contains(&token) {
            config.supported_tokens.push(token);
        }
    }
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "add_supported_tokens")
        .add_attribute("status", "success"))
}

pub fn execute_remove_supported_tokens(
    deps: DepsMut,
    info: MessageInfo,
    tokens: Vec<String>,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    let owners = OWNERS.load(deps.storage)?;
    if !owners.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    config
        .supported_tokens
        .retain(|token| !tokens.contains(token));
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "remove_supported_tokens")
        .add_attribute("status", "success"))
}

pub fn execute_add_supported_protocols(
    deps: DepsMut,
    info: MessageInfo,
    protocols: Vec<String>,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    let owners = OWNERS.load(deps.storage)?;
    if !owners.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    for protocol in protocols {
        if !config.supported_protocols.contains(&protocol) {
            config.supported_protocols.push(protocol);
        }
    }
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "add_supported_protocols")
        .add_attribute("status", "success"))
}

pub fn execute_remove_supported_protocols(
    deps: DepsMut,
    info: MessageInfo,
    protocols: Vec<String>,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    let owners = OWNERS.load(deps.storage)?;
    if !owners.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    config
        .supported_protocols
        .retain(|protocol| !protocols.contains(protocol));
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "remove_supported_protocols")
        .add_attribute("status", "success"))
}

pub fn execute_update_default_timeout_height(
    deps: DepsMut,
    info: MessageInfo,
    default_timeout_height: u64,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    let owners = OWNERS.load(deps.storage)?;
    if !owners.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    config.default_timeout_height = default_timeout_height;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "update_default_timeout_height")
        .add_attribute("status", "success"))
}

pub fn execute_add_ibc_connection(
    deps: DepsMut,
    info: MessageInfo,
    env: Env,
    chain_id: String,
    port: String,
    channel_id: String,
) -> Result<Response, ContractError> {
    let owners = OWNERS.load(deps.storage)?;
    if !owners.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    IBC_CONNECTIONS.save(
        deps.storage,
        &chain_id,
        &Connection {
            chain_id: chain_id.clone(),
            port,
            channel_id,
            is_active: true,
            last_updated: env.block.time,
        },
    )?;

    Ok(Response::new()
        .add_attribute("action", "add_ibc_connection")
        .add_attribute("chain_id", chain_id)
        .add_attribute("status", "success"))
}

pub fn execute_update_ibc_connection(
    deps: DepsMut,
    info: MessageInfo,
    env: Env,
    chain_id: String,
    port: Option<String>,
    channel_id: Option<String>,
    is_active: Option<bool>,
) -> Result<Response, ContractError> {
    let owners = OWNERS.load(deps.storage)?;
    if !owners.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    let mut connection = IBC_CONNECTIONS.load(deps.storage, &chain_id)?;
    if let Some(port) = port {
        connection.port = port;
    }
    if let Some(channel_id) = channel_id {
        connection.channel_id = channel_id;
    }
    if let Some(is_active) = is_active {
        connection.is_active = is_active;
    }

    connection.last_updated = env.block.time;
    IBC_CONNECTIONS.save(deps.storage, &chain_id, &connection)?;

    Ok(Response::new()
        .add_attribute("action", "update_ibc_connection")
        .add_attribute("chain_id", chain_id)
        .add_attribute("status", "success"))
}

pub fn execute_remove_ibc_connection(
    deps: DepsMut,
    info: MessageInfo,
    chain_id: String,
) -> Result<Response, ContractError> {
    let owners = OWNERS.load(deps.storage)?;
    if !owners.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    IBC_CONNECTIONS.remove(deps.storage, &chain_id);

    Ok(Response::new()
        .add_attribute("action", "remove_ibc_connection")
        .add_attribute("chain_id", chain_id)
        .add_attribute("status", "success"))
}

pub fn execute_propose_config_update(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    proposal_id: u64,
    threshold: Option<u32>,
    supported_tokens: Option<Vec<String>>,
    supported_protocols: Option<Vec<String>>,
    default_timeout_height: Option<u64>,
) -> Result<Response, ContractError> {
    let owners = OWNERS.load(deps.storage)?;
    if !owners.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    if CONFIG_PROPOSALS
        .may_load(deps.storage, &proposal_id)?
        .is_some()
    {
        return Err(ContractError::ValidationError(
            "Proposal ID already exists".to_string(),
        ));
    }

    let config = UpdateConfig {
        supported_tokens,
        supported_protocols,
        default_timeout_height,
        max_intent_duration: None,
        min_intent_amount: None,
        emergency_pause: None,
        rate_limit_per_user: None,
    };

    let proposal = ConfigProposal {
        proposal_id,
        proposer: info.sender.clone(),
        config,
        approvals: vec![info.sender.clone()],
        created_at: env.block.time,
        expiry: env.block.time.plus_seconds(7 * 24 * 60 * 60), // 7 days expiry
        threshold,
    };

    CONFIG_PROPOSALS.save(deps.storage, &proposal_id, &proposal)?;
    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_attribute("action", "propose_config_update")
        .add_attribute("proposal_id", proposal_id.to_string())
        .add_attribute("proposer", info.sender.to_string()))
}

pub fn execute_approve_config_proposal(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    proposal_id: u64,
) -> Result<Response, ContractError> {
    let owners = OWNERS.load(deps.storage)?;
    if !owners.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    let mut proposal = CONFIG_PROPOSALS.load(deps.storage, &proposal_id)?;
    if proposal.approvals.contains(&info.sender) {
        return Err(ContractError::ValidationError(
            "Sender has already approved this proposal".to_string(),
        ));
    }
    proposal.approvals.push(info.sender.clone());
    CONFIG_PROPOSALS.save(deps.storage, &proposal_id, &proposal)?;
    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_attribute("action", "approve_config_proposal")
        .add_attribute("proposal_id", proposal_id.to_string())
        .add_attribute("approver", info.sender.to_string()))
}

pub fn execute_execute_config_proposal(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    proposal_id: u64,
) -> Result<Response, ContractError> {
    let owners = OWNERS.load(deps.storage)?;
    if !owners.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }

    let proposal = CONFIG_PROPOSALS.load(deps.storage, &proposal_id)?;
    if env.block.time > proposal.expiry {
        return Err(ContractError::ValidationError(
            "Proposal has expired".to_string(),
        ));
    }

    let threshold = THRESHOLD.load(deps.storage)?;
    if (proposal.approvals.len() as u32) < threshold {
        return Err(ContractError::ValidationError(
            "Not enough approvals to execute proposal".to_string(),
        ));
    }

    let mut config = CONFIG.load(deps.storage)?;
    if let Some(tokens) = &proposal.config.supported_tokens {
        config.supported_tokens = tokens.clone();
    }
    if let Some(protocols) = &proposal.config.supported_protocols {
        config.supported_protocols = protocols.clone();
    }
    if let Some(timeout) = proposal.config.default_timeout_height {
        config.default_timeout_height = timeout;
    }
    if let Some(max_duration) = proposal.config.max_intent_duration {
        config.max_intent_duration = max_duration;
    }
    if let Some(min_amount) = proposal.config.min_intent_amount {
        config.min_intent_amount = min_amount;
    }
    if let Some(emergency_pause) = proposal.config.emergency_pause {
        config.emergency_pause = emergency_pause;
    }
    if let Some(rate_limit) = proposal.config.rate_limit_per_user {
        config.rate_limit_per_user = rate_limit;
    }

    if let Some(new_threshold) = proposal.threshold {
        if new_threshold as usize > owners.len() || new_threshold == 0 {
            return Err(ContractError::ValidationError(
                "Invalid threshold configuration".to_string(),
            ));
        }
        THRESHOLD.save(deps.storage, &new_threshold)?;
    }

    CONFIG.save(deps.storage, &config)?;
    CONFIG_PROPOSALS.remove(deps.storage, &proposal_id);
    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_attribute("action", "execute_config_proposal")
        .add_attribute("proposal_id", proposal_id.to_string()))
}

pub fn execute_initiate_recovery(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    proposed_owner: Addr,
) -> Result<Response, ContractError> {
    let guardians = GUARDIANS.load(deps.storage)?;
    if !guardians.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    let mut recovery = RECOVERY.load(deps.storage)?;
    if recovery.proposed_owner.is_some() {
        return Err(ContractError::ValidationError(
            "Recovery already in progress".to_string(),
        ));
    }
    recovery.proposed_owner = Some(proposed_owner.clone());
    recovery.initiated_at = Some(env.block.time);
    recovery.guardian_approvals = vec![info.sender.clone()];
    RECOVERY.save(deps.storage, &recovery)?;
    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_attribute("action", "initiate_recovery")
        .add_attribute("proposed_owner", proposed_owner.to_string())
        .add_attribute("initiator", info.sender.to_string()))
}

pub fn execute_approve_recovery(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let guardians = GUARDIANS.load(deps.storage)?;
    if !guardians.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    let mut recovery = RECOVERY.load(deps.storage)?;
    if recovery.proposed_owner.is_none() {
        return Err(ContractError::ValidationError(
            "No recovery proposal active".to_string(),
        ));
    }
    if recovery.guardian_approvals.contains(&info.sender) {
        return Err(ContractError::ValidationError(
            "Sender has already approved recovery".to_string(),
        ));
    }
    recovery.guardian_approvals.push(info.sender.clone());
    if (recovery.guardian_approvals.len() as u32) >= recovery.threshold
        && env.block.time.seconds() >= recovery.initiated_at.unwrap().seconds() + recovery.delay
    {
        let mut config = CONFIG.load(deps.storage)?;
        config.admin = recovery.proposed_owner.take().unwrap();
        CONFIG.save(deps.storage, &config)?;
        recovery.initiated_at = None;
        recovery.guardian_approvals = vec![];
        RECOVERY.save(deps.storage, &recovery)?;
    } else {
        RECOVERY.save(deps.storage, &recovery)?;
    }
    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_attribute("action", "approve_recovery")
        .add_attribute("approver", info.sender.to_string()))
}

pub fn execute_trigger_circuit_breaker(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    reason: String,
) -> Result<Response, ContractError> {
    let guardians = GUARDIANS.load(deps.storage)?;
    if !guardians.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    let mut circuit_breaker = CIRCUIT_BREAKER.load(deps.storage)?;
    if circuit_breaker.is_triggered {
        return Err(ContractError::ValidationError(
            "Circuit breaker already triggered".to_string(),
        ));
    }
    circuit_breaker.is_triggered = true;
    circuit_breaker.trigger_reason = Some(reason.clone());
    circuit_breaker.triggered_at = Some(env.block.time);
    circuit_breaker.triggered_by = Some(info.sender.clone());
    CIRCUIT_BREAKER.save(deps.storage, &circuit_breaker)?;
    update_health_status(
        deps,
        &env,
        false,
        Some("Circuit breaker triggered".to_string()),
    )?;

    Ok(Response::new()
        .add_attribute("action", "trigger_circuit_breaker")
        .add_attribute("reason", reason)
        .add_attribute("triggered_by", info.sender.to_string()))
}

pub fn execute_reset_circuit_breaker(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let guardians = GUARDIANS.load(deps.storage)?;
    if !guardians.contains(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    let mut circuit_breaker = CIRCUIT_BREAKER.load(deps.storage)?;
    if !circuit_breaker.is_triggered {
        return Err(ContractError::ValidationError(
            "Circuit breaker not triggered".to_string(),
        ));
    }
    if circuit_breaker.reset_approvals.contains(&info.sender) {
        return Err(ContractError::ValidationError(
            "Sender has already approved reset".to_string(),
        ));
    }
    circuit_breaker.reset_approvals.push(info.sender.clone());
    if (circuit_breaker.reset_approvals.len() as u32) >= circuit_breaker.reset_threshold {
        circuit_breaker.is_triggered = false;
        circuit_breaker.trigger_reason = None;
        circuit_breaker.triggered_at = None;
        circuit_breaker.triggered_by = None;
        circuit_breaker.reset_approvals = vec![];
        CIRCUIT_BREAKER.save(deps.storage, &circuit_breaker)?;
    } else {
        CIRCUIT_BREAKER.save(deps.storage, &circuit_breaker)?;
    }
    update_health_status(deps, &env, true, None)?;

    Ok(Response::new()
        .add_attribute("action", "reset_circuit_breaker")
        .add_attribute("approver", info.sender.to_string()))
}

fn calculate_gas_price(fee_structure: &FeeStructure, priority: &Priority) -> Uint128 {
    let multiplier = fee_structure
        .priority_multiplier
        .iter()
        .find(|(p, _)| p == priority)
        .map(|(_, m)| *m)
        .unwrap_or(100);
    fee_structure.gas_price * Uint128::from(multiplier) / Uint128::from(100u32)
}

fn deduct_gas_payment(
    storage: &mut dyn cosmwasm_std::Storage,
    env: &Env,
    info: &MessageInfo,
    paymaster_reserve: &mut PaymasterReserve,
    config: &Config,
    gas_price: Uint128,
    max_gas: Uint128,
    use_wallet_balance: bool,
) -> Result<GasPaymentResult, ContractError> {
    let mut messages = vec![];

    // Check rate limit
    let period = env.block.time.seconds() / (24 * 3600); // Daily bucket
    let mut current_rate = RATE_LIMITS
        .may_load(storage, (&info.sender.clone(), period))?
        .unwrap_or(RateLimit {
            user: info.sender.clone(),
            day: env.block.time.seconds() / 86400,
            count: 0,
        });
    if current_rate.count >= config.rate_limit_per_user {
        return Err(ContractError::ValidationError(
            "Rate limit exceeded".to_string(),
        ));
    }
    current_rate.count += 1;
    RATE_LIMITS.save(storage, (&info.sender, period), &current_rate)?;

    // Check if gas_price is within max_gas limit
    if gas_price > max_gas {
        return Err(ContractError::ValidationError(format!(
            "Gas price {} exceeds max allowed {}",
            gas_price, max_gas
        )));
    }

    // Try wallet balance first if allowed
    if use_wallet_balance {
        let mut wallet_balance =
            WALLET_BALANCES
                .may_load(storage, &info.sender)?
                .unwrap_or(WalletBalance {
                    address: info.sender.clone(),
                    balances: vec![],
                });

        // Find the index of a suitable balance
        let balance_index = wallet_balance.balances.iter().position(|b| {
            b.is_native && config.supported_tokens.contains(&b.token) && b.amount >= gas_price
        });

        if let Some(index) = balance_index {
            let balance = &mut wallet_balance.balances[index];
            let denom = balance.token.clone();
            balance.amount -= gas_price;
            WALLET_BALANCES.save(storage, &info.sender, &wallet_balance)?;
            messages.push(
                BankMsg::Send {
                    to_address: env.contract.address.to_string(),
                    amount: vec![Coin {
                        denom,
                        amount: gas_price,
                    }],
                }
                .into(),
            );
            return Ok(GasPaymentResult { messages });
        }
    }

    // Try transaction funds
    for fund in &info.funds {
        if config.supported_tokens.contains(&fund.denom) && fund.amount >= gas_price {
            messages.push(
                BankMsg::Send {
                    to_address: env.contract.address.to_string(),
                    amount: vec![Coin {
                        denom: fund.denom.clone(),
                        amount: gas_price,
                    }],
                }
                .into(),
            );
            return Ok(GasPaymentResult { messages });
        }
    }

    // Fall back to paymaster reserve
    if let Some(reserve) = paymaster_reserve.balances.iter_mut().find(|b| {
        b.is_native && config.supported_tokens.contains(&b.token) && b.amount >= gas_price
    }) {
        reserve.amount -= gas_price;
        messages.push(
            BankMsg::Send {
                to_address: env.contract.address.to_string(),
                amount: vec![Coin {
                    denom: reserve.token.clone(),
                    amount: gas_price,
                }],
            }
            .into(),
        );
        return Ok(GasPaymentResult { messages });
    }

    Err(ContractError::ValidationError(
        "Insufficient funds for gas payment".to_string(),
    ))
}

#[derive(Debug)]
struct GasPaymentResult {
    messages: Vec<CosmosMsg>,
}

fn add_cw20_transfer_msg(token_address: &str, to: &Addr, amount: Uint128) -> StdResult<CosmosMsg> {
    Ok(WasmMsg::Execute {
        contract_addr: token_address.to_string(),
        msg: to_json_binary(&Cw20ExecuteMsg::Transfer {
            recipient: to.to_string(),
            amount,
        })?,
        funds: vec![],
    }
    .into())
}

fn add_native_transfer_msg(denom: &str, to: &Addr, amount: Uint128) -> StdResult<CosmosMsg> {
    Ok(BankMsg::Send {
        to_address: to.to_string(),
        amount: vec![Coin {
            denom: denom.to_string(),
            amount,
        }],
    }
    .into())
}

fn update_health_status(
    deps: DepsMut,
    env: &Env,
    is_healthy: bool,
    issue: Option<String>,
) -> StdResult<()> {
    let mut health_status = HEALTH_STATUS.load(deps.storage)?;
    health_status.is_healthy = is_healthy;
    health_status.last_check = env.block.time;
    health_status.last_check_height = env.block.height;
    if let Some(issue) = issue {
        health_status.issues.push(issue);
    }
    if !is_healthy {
        health_status.metrics.failed_executions += 1;
    } else {
        health_status.metrics.successful_executions += 1;
    }
    HEALTH_STATUS.save(deps.storage, &health_status)?;
    Ok(())
}

#[cfg(test)]
mod execute_tests {
    use super::*;
    use crate::types::*;
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{Addr, Uint128, coins};

    fn setup_test_env() -> (cosmwasm_std::testing::MockStorage, Env, MessageInfo) {
        let mut storage = MockStorage::new();
        let env = mock_env();
        let info = message_info(&Addr::unchecked("user"), &coins(1000, "uatom"));

        // Initialize required state
        let config = Config {
            admin: Addr::unchecked("admin"),
            supported_tokens: vec!["uatom".to_string(), "ujuno".to_string()],
            supported_protocols: vec!["juno".to_string(), "osmosis".to_string()],
            default_timeout_height: 1000,
            fee_collector: Addr::unchecked("fee_collector"),
            max_intent_duration: 86400,
            min_intent_amount: Uint128::from(100u128),
            emergency_pause: false,
            rate_limit_per_user: 100,
        };
        CONFIG.save(&mut storage, &config).unwrap();

        let owners = vec![Addr::unchecked("admin")];
        OWNERS.save(&mut storage, &owners).unwrap();

        let guardians = vec![Addr::unchecked("guardian")];
        GUARDIANS.save(&mut storage, &guardians).unwrap();

        let paymaster_reserve = PaymasterReserve {
            balances: vec![BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(10000u128),
                is_native: true,
            }],
        };
        PAYMASTER_RESERVE
            .save(&mut storage, &paymaster_reserve)
            .unwrap();

        let fee_structure = FeeStructure {
            base_fee: Uint128::from(10u128),
            percentage_fee: 50,
            gas_price: Uint128::from(100u128),
            priority_multiplier: vec![
                (Priority::Low, 100),
                (Priority::Normal, 150),
                (Priority::High, 200),
                (Priority::Urgent, 300),
            ],
        };
        FEE_STRUCTURE.save(&mut storage, &fee_structure).unwrap();

        let circuit_breaker = CircuitBreakerState {
            is_triggered: false,
            trigger_reason: None,
            triggered_at: None,
            triggered_by: None,
            reset_approvals: vec![],
            reset_threshold: 1,
        };
        CIRCUIT_BREAKER
            .save(&mut storage, &circuit_breaker)
            .unwrap();

        let health_status = HealthStatus {
            is_healthy: true,
            last_check: env.block.time,
            last_check_height: env.block.height,
            issues: vec![],
            metrics: HealthMetrics {
                total_intents: 0,
                active_intents: 0,
                successful_executions: 0,
                failed_executions: 0,
                average_execution_time: 0,
                total_value_locked: Uint128::zero(),
            },
        };
        HEALTH_STATUS.save(&mut storage, &health_status).unwrap();

        (storage, env, info)
    }

    #[test]
    fn test_execute_create_intent() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();
        PAYMASTER_RESERVE
            .save(&mut deps.storage, &paymaster_reserve)
            .unwrap();
        let fee_structure = FEE_STRUCTURE.load(&storage).unwrap();
        FEE_STRUCTURE
            .save(&mut deps.storage, &fee_structure)
            .unwrap();
        let circuit_breaker = CIRCUIT_BREAKER.load(&storage).unwrap();
        CIRCUIT_BREAKER
            .save(&mut deps.storage, &circuit_breaker)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Set info sender to a valid user
        info.sender = Addr::unchecked("user");
        info.funds = vec![Coin {
            denom: "uatom".to_string(),
            amount: Uint128::from(1010u128), // input_tokens (1000) + tip (10)
        }];

        let input_tokens = vec![BeepCoin {
            token: "uatom".to_string(),
            amount: Uint128::from(1000u128),
            is_native: true,
        }];

        let intent_type = IntentType::Swap {
            output_tokens: vec![ExpectedToken {
                token: "ujuno".to_string(),
                is_native: true,
                amount: Uint128::from(500u128),
                target_address: None,
            }],
        };

        let tip = BeepCoin {
            token: "uatom".to_string(),
            amount: Uint128::from(10u128),
            is_native: true,
        };

        let result = execute_create_intent(
            deps.as_mut(),
            env,
            info,
            "intent_1".to_string(),
            input_tokens,
            intent_type,
            "juno-1".to_string(),
            Some(2000),
            tip,
            Some(100),
            true,
            Priority::Normal,
            false, // Use transaction funds, not wallet balance
        );

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes.len(), 4);
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "create_intent");

        // Verify intent was saved
        let intent = INTENTS.load(&deps.storage, "intent_1").unwrap();
        assert_eq!(intent.id, "intent_1");
        assert_eq!(intent.status, IntentStatus::Active);
        assert_eq!(intent.creator, Addr::unchecked("user"));
    }

    #[test]
    fn test_execute_create_intent_cw20() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Configure mock querier to handle CW20 contract queries
        deps.querier.update_wasm(|query| {
            match query {
                cosmwasm_std::WasmQuery::Smart { contract_addr, msg } => {
                    if contract_addr == "cw20_token" {
                        match cosmwasm_std::from_json::<cw20::Cw20QueryMsg>(msg) {
                            Ok(cw20::Cw20QueryMsg::Balance { address }) => {
                                let balance_response = cw20::BalanceResponse {
                                    balance: if address == "user" {
                                        Uint128::from(2000u128) // Sufficient balance
                                    } else {
                                        Uint128::zero()
                                    },
                                };
                                cosmwasm_std::SystemResult::Ok(cosmwasm_std::ContractResult::Ok(
                                    cosmwasm_std::to_json_binary(&balance_response).unwrap(),
                                ))
                            }
                            Ok(cw20::Cw20QueryMsg::Allowance { owner, spender: _ }) => {
                                let allowance_response = cw20::AllowanceResponse {
                                    allowance: if owner == "user" {
                                        Uint128::from(2000u128) // Sufficient allowance
                                    } else {
                                        Uint128::zero()
                                    },
                                    expires: cw20::Expiration::Never {},
                                };
                                cosmwasm_std::SystemResult::Ok(cosmwasm_std::ContractResult::Ok(
                                    cosmwasm_std::to_json_binary(&allowance_response).unwrap(),
                                ))
                            }
                            _ => cosmwasm_std::SystemResult::Err(
                                cosmwasm_std::SystemError::UnsupportedRequest {
                                    kind: "unsupported CW20 query".to_string(),
                                },
                            ),
                        }
                    } else {
                        cosmwasm_std::SystemResult::Err(cosmwasm_std::SystemError::NoSuchContract {
                            addr: contract_addr.clone(),
                        })
                    }
                }
                _ => {
                    cosmwasm_std::SystemResult::Err(cosmwasm_std::SystemError::UnsupportedRequest {
                        kind: "unsupported query".to_string(),
                    })
                }
            }
        });

        // Copy state from storage to deps.storage
        let mut config = CONFIG.load(&storage).unwrap();
        // Add CW20 token to supported_tokens
        config.supported_tokens.push("cw20_token".to_string());
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();
        PAYMASTER_RESERVE
            .save(&mut deps.storage, &paymaster_reserve)
            .unwrap();
        let fee_structure = FEE_STRUCTURE.load(&storage).unwrap();
        FEE_STRUCTURE
            .save(&mut deps.storage, &fee_structure)
            .unwrap();
        let circuit_breaker = CIRCUIT_BREAKER.load(&storage).unwrap();
        CIRCUIT_BREAKER
            .save(&mut deps.storage, &circuit_breaker)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Set info sender and funds for gas only (CW20 tokens don't require native funds)
        info.sender = Addr::unchecked("user");
        info.funds = vec![Coin {
            denom: "uatom".to_string(),
            amount: Uint128::from(150u128), // Cover gas (100 * 150 / 100)
        }];

        let input_tokens = vec![BeepCoin {
            token: "cw20_token".to_string(),
            amount: Uint128::from(1000u128),
            is_native: false,
        }];

        let intent_type = IntentType::Swap {
            output_tokens: vec![ExpectedToken {
                token: "ujuno".to_string(),
                is_native: true,
                amount: Uint128::from(500u128),
                target_address: None,
            }],
        };

        let tip = BeepCoin {
            token: "cw20_token".to_string(),
            amount: Uint128::from(10u128),
            is_native: false,
        };

        let result = execute_create_intent(
            deps.as_mut(),
            env,
            info,
            "intent_1".to_string(),
            input_tokens,
            intent_type,
            "juno-1".to_string(),
            Some(2000),
            tip,
            Some(100),
            true, // Allow partial fill
            Priority::Normal,
            false, // Use transaction funds (CW20 messages)
        );

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes.len(), 4);
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "create_intent");

        // Verify intent was saved
        let intent = INTENTS.load(&deps.storage, "intent_1").unwrap();
        assert_eq!(intent.id, "intent_1");
        assert_eq!(intent.status, IntentStatus::Active);
        assert_eq!(intent.creator, Addr::unchecked("user"));

        // Verify response contains CW20 transfer messages
        assert!(
            !response.messages.is_empty(),
            "Expected CW20 transfer messages"
        );
    }

    #[test]
    fn test_execute_fill_intent() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();
        PAYMASTER_RESERVE
            .save(&mut deps.storage, &paymaster_reserve)
            .unwrap();
        let fee_structure = FEE_STRUCTURE.load(&storage).unwrap();
        FEE_STRUCTURE
            .save(&mut deps.storage, &fee_structure)
            .unwrap();
        let circuit_breaker = CIRCUIT_BREAKER.load(&storage).unwrap();
        CIRCUIT_BREAKER
            .save(&mut deps.storage, &circuit_breaker)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Create and save intent to deps.storage
        let intent = Intent {
            id: "intent_1".to_string(),
            creator: Addr::unchecked("creator"),
            input_tokens: vec![BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(1000u128),
                is_native: true,
            }],
            intent_type: IntentType::Swap {
                output_tokens: vec![ExpectedToken {
                    token: "ujuno".to_string(),
                    is_native: true,
                    amount: Uint128::from(500u128),
                    target_address: None,
                }],
            },
            executor: None,
            status: IntentStatus::Active,
            created_at: env.block.height,
            origin_chain_id: env.block.chain_id.clone(),
            target_chain_id: env.block.chain_id.clone(),
            timeout: env.block.height + 1000,
            tip: BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(10u128),
                is_native: true,
            },
            max_slippage: Some(100),
            partial_fill_allowed: true,
            filled_amount: Uint128::zero(),
            execution_fee: Uint128::zero(),
            retry_count: 0,
            priority: Priority::Normal,
        };
        INTENTS
            .save(&mut deps.storage, "intent_1", &intent)
            .unwrap();

        // Add funds for output tokens and gas
        info.sender = Addr::unchecked("executor"); // Set sender to a different address
        info.funds = vec![
            Coin {
                denom: "ujuno".to_string(),
                amount: Uint128::from(500u128), // Match expected output
            },
            Coin {
                denom: "uatom".to_string(),
                amount: Uint128::from(150u128), // Gas (100 * 150 / 100)
            },
        ];

        let result = execute_fill_intent(
            deps.as_mut(),
            env.clone(),
            info,
            "intent_1".to_string(),
            env.block.chain_id, // Match intent.target_chain_id
            intent.intent_type.clone(),
            false, // Same-chain fill
        );

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "fill_intent_same_chain");

        // Verify intent was updated
        let updated_intent = INTENTS.load(&deps.storage, "intent_1").unwrap();
        assert_eq!(updated_intent.status, IntentStatus::Completed);
        assert_eq!(updated_intent.executor, Some(Addr::unchecked("executor")));
        assert_eq!(updated_intent.filled_amount, Uint128::from(500u128));
    }

    #[test]
    fn test_execute_cancel_intent() {
        let (storage, env, info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();
        PAYMASTER_RESERVE
            .save(&mut deps.storage, &paymaster_reserve)
            .unwrap();
        let fee_structure = FEE_STRUCTURE.load(&storage).unwrap();
        FEE_STRUCTURE
            .save(&mut deps.storage, &fee_structure)
            .unwrap();
        let circuit_breaker = CIRCUIT_BREAKER.load(&storage).unwrap();
        CIRCUIT_BREAKER
            .save(&mut deps.storage, &circuit_breaker)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Create and save intent to deps.storage
        let intent = Intent {
            id: "intent_1".to_string(),
            creator: info.sender.clone(), // "user"
            input_tokens: vec![BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(1000u128),
                is_native: true,
            }],
            intent_type: IntentType::Swap {
                output_tokens: vec![ExpectedToken {
                    token: "ujuno".to_string(),
                    is_native: true,
                    amount: Uint128::from(500u128),
                    target_address: None,
                }],
            },
            executor: None,
            status: IntentStatus::Active,
            created_at: env.block.height,
            origin_chain_id: env.block.chain_id.clone(),
            target_chain_id: "juno-1".to_string(),
            timeout: env.block.height + 1000,
            tip: BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(10u128),
                is_native: true,
            },
            max_slippage: Some(100),
            partial_fill_allowed: true,
            filled_amount: Uint128::zero(),
            execution_fee: Uint128::zero(),
            retry_count: 0,
            priority: Priority::Normal,
        };
        INTENTS
            .save(&mut deps.storage, "intent_1", &intent)
            .unwrap();
        ESCROW
            .save(
                &mut deps.storage,
                (&info.sender, "intent_1"),
                &intent.input_tokens,
            )
            .unwrap();

        // Initialize WALLET_BALANCES for gas payment
        let wallet_balance = WalletBalance {
            address: info.sender.clone(),
            balances: vec![BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(150u128), // Gas (100 * 150 / 100)
                is_native: true,
            }],
        };
        WALLET_BALANCES
            .save(&mut deps.storage, &info.sender, &wallet_balance)
            .unwrap();

        let result = execute_cancel_intent(deps.as_mut(), env, info, "intent_1".to_string());

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "cancel_intent");

        // Verify intent was updated
        let updated_intent = INTENTS.load(&deps.storage, "intent_1").unwrap();
        assert_eq!(updated_intent.status, IntentStatus::Cancelled);
    }

    #[test]
    fn test_execute_deposit_to_wallet() {
        let (storage, env, info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let mut config = CONFIG.load(&storage).unwrap();
        // Ensure "uatom" is in supported_tokens
        if !config.supported_tokens.contains(&"uatom".to_string()) {
            config.supported_tokens.push("uatom".to_string());
        }
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();
        PAYMASTER_RESERVE
            .save(&mut deps.storage, &paymaster_reserve)
            .unwrap();
        let fee_structure = FEE_STRUCTURE.load(&storage).unwrap();
        FEE_STRUCTURE
            .save(&mut deps.storage, &fee_structure)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        let tokens = vec![BeepCoin {
            token: "uatom".to_string(),
            amount: Uint128::from(1000u128),
            is_native: true,
        }];

        let result = execute_deposit_to_wallet(deps.as_mut(), env, info.clone(), tokens);

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "deposit_to_wallet");
        assert_eq!(response.attributes[1].key, "user");
        assert_eq!(response.attributes[1].value, info.sender.to_string());

        // Check that wallet balance was created
        let wallet_balance = WALLET_BALANCES.load(&deps.storage, &info.sender).unwrap();
        assert!(
            wallet_balance
                .balances
                .iter()
                .any(|b| b.token == "uatom" && b.amount == Uint128::from(995u128)) // 1000 - 0.5% fee
        );
    }

    #[test]
    fn test_execute_transfer_from_wallet() {
        let (storage, env, info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();
        PAYMASTER_RESERVE
            .save(&mut deps.storage, &paymaster_reserve)
            .unwrap();
        let fee_structure = FEE_STRUCTURE.load(&storage).unwrap();
        FEE_STRUCTURE
            .save(&mut deps.storage, &fee_structure)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Set up wallet balance
        let wallet_balance = WalletBalance {
            address: info.sender.clone(),
            balances: vec![BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(1000u128),
                is_native: true,
            }],
        };
        WALLET_BALANCES
            .save(&mut deps.storage, &info.sender, &wallet_balance)
            .unwrap();

        let tokens = vec![BeepCoin {
            token: "uatom".to_string(),
            amount: Uint128::from(500u128),
            is_native: true,
        }];

        let recipient = Addr::unchecked("recipient");

        let result = execute_transfer_from_wallet(
            deps.as_mut(),
            env,
            info.clone(),
            recipient.clone(),
            tokens,
        );

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "transfer_from_wallet");
        assert_eq!(response.attributes[1].key, "recipient");
        assert_eq!(response.attributes[1].value, recipient.to_string());
    }

    #[test]
    fn test_execute_paymaster_fund() {
        let (storage, env, info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let mut config = CONFIG.load(&storage).unwrap();
        // Ensure "uatom" is in supported_tokens
        if !config.supported_tokens.contains(&"uatom".to_string()) {
            config.supported_tokens.push("uatom".to_string());
        }
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();
        PAYMASTER_RESERVE
            .save(&mut deps.storage, &paymaster_reserve)
            .unwrap();
        let fee_structure = FEE_STRUCTURE.load(&storage).unwrap();
        FEE_STRUCTURE
            .save(&mut deps.storage, &fee_structure)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        let tokens = vec![BeepCoin {
            token: "uatom".to_string(),
            amount: Uint128::from(1000u128),
            is_native: true,
        }];

        let result = execute_paymaster_fund(deps.as_mut(), env, info.clone(), tokens);

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "paymaster_fund");
        assert_eq!(response.attributes[1].key, "user");
        assert_eq!(response.attributes[1].value, info.sender.to_string());

        // Check that paymaster reserve was updated
        let paymaster_reserve = PAYMASTER_RESERVE.load(&deps.storage).unwrap();
        assert!(
            paymaster_reserve
                .balances
                .iter()
                .any(|b| b.token == "uatom" && b.amount >= Uint128::from(1000u128))
        );
    }

    #[test]
    fn test_execute_initiate_user_recovery() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Ensure "guardian" is in GUARDIANS
        let mut guardians = guardians;
        if !guardians.contains(&Addr::unchecked("guardian")) {
            guardians.push(Addr::unchecked("guardian"));
            GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        }

        // Set info sender as guardian
        info.sender = Addr::unchecked("guardian");

        let user = Addr::unchecked("user_to_recover");
        let new_address = Addr::unchecked("new_user_address");

        let result = execute_initiate_user_recovery(
            deps.as_mut(),
            env,
            info.clone(),
            user.clone(),
            new_address.clone(),
        );

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "initiate_user_recovery");
        assert_eq!(response.attributes[1].key, "user");
        assert_eq!(response.attributes[1].value, user.to_string());
        assert_eq!(response.attributes[2].key, "new_address");
        assert_eq!(response.attributes[2].value, new_address.to_string());
        assert_eq!(response.attributes[3].key, "initiator");
        assert_eq!(response.attributes[3].value, info.sender.to_string());

        // Check that recovery was created
        let recovery = USER_RECOVERIES.load(&deps.storage, &user).unwrap();
        assert_eq!(recovery.new_address, Some(new_address));
        assert_eq!(recovery.guardian_approvals, vec![info.sender]);
    }

    #[test]
    fn test_execute_approve_user_recovery() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();
        // Initialize CONFIG and WALLET_BALANCES to be safe
        let config = CONFIG.load(&storage).unwrap_or(Config {
            supported_tokens: vec![],
            supported_protocols: vec![],
            default_timeout_height: 0,
            max_intent_duration: 0,
            min_intent_amount: Uint128::zero(),
            emergency_pause: false,
            rate_limit_per_user: 0,
            admin: Addr::unchecked("admin"),
            fee_collector: Addr::unchecked("fee_collector"),
        });
        CONFIG.save(&mut deps.storage, &config).unwrap();
        // Initialize empty WALLET_BALANCES for user to avoid potential issues
        WALLET_BALANCES
            .save(
                &mut deps.storage,
                &Addr::unchecked("user_to_recover"),
                &WalletBalance {
                    address: Addr::unchecked("user_to_recover"),
                    balances: vec![],
                },
            )
            .unwrap();

        let user = Addr::unchecked("user_to_recover");

        // Set up existing recovery
        let recovery = UserRecovery {
            user: user.clone(),
            new_address: Some(Addr::unchecked("new_address")),
            initiated_at: Some(env.block.time),
            guardian_approvals: vec![Addr::unchecked("guardian1")],
            threshold: 2,
            delay: 48 * 3600,
        };
        USER_RECOVERIES
            .save(&mut deps.storage, &user, &recovery)
            .unwrap();

        // Ensure "guardian" is in GUARDIANS
        let mut guardians = guardians;
        if !guardians.contains(&Addr::unchecked("guardian")) {
            guardians.push(Addr::unchecked("guardian"));
            GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        }

        // Set info sender as different guardian
        info.sender = Addr::unchecked("guardian");

        let result = execute_approve_user_recovery(deps.as_mut(), env, info.clone(), user.clone());

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "approve_user_recovery");
        assert_eq!(response.attributes[1].key, "user");
        assert_eq!(response.attributes[1].value, user.to_string());
        assert_eq!(response.attributes[2].key, "approver");
        assert_eq!(response.attributes[2].value, info.sender.to_string());

        // Check that approval was added
        let updated_recovery = USER_RECOVERIES.load(&deps.storage, &user).unwrap();
        assert!(updated_recovery.guardian_approvals.contains(&info.sender));
    }

    #[test]
    fn test_execute_update_admin() {
        let (storage, _env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();

        // Ensure "admin" is in OWNERS
        let mut owners = owners;
        if !owners.contains(&Addr::unchecked("admin")) {
            owners.push(Addr::unchecked("admin"));
            OWNERS.save(&mut deps.storage, &owners).unwrap();
        }

        // Set info sender as owner
        info.sender = Addr::unchecked("admin");
        let new_admin = Addr::unchecked("new_admin");

        let result = execute_update_admin(deps.as_mut(), info.clone(), new_admin.clone());

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "update_admin");
        assert_eq!(response.attributes[1].key, "old_admin");
        assert_eq!(response.attributes[1].value, "admin");
        assert_eq!(response.attributes[2].key, "new_admin");
        assert_eq!(response.attributes[2].value, "new_admin");

        // Check that admin was updated
        let config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.admin, new_admin);
    }

    #[test]
    fn test_execute_add_supported_tokens() {
        let (storage, _env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy initial state from storage to deps.storage
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();

        let mut owners = OWNERS.load(&storage).unwrap();
        // Ensure "admin" is in OWNERS
        if !owners.contains(&Addr::unchecked("admin")) {
            owners.push(Addr::unchecked("admin"));
        }
        OWNERS.save(&mut deps.storage, &owners).unwrap();

        // Set info sender as owner
        info.sender = Addr::unchecked("admin");
        let new_tokens = vec!["uosmo".to_string(), "uakt".to_string()];

        let result = execute_add_supported_tokens(deps.as_mut(), info, new_tokens.clone());

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();

        // Check attributes without assuming order
        fn has_attribute(attrs: &[cosmwasm_std::Attribute], key: &str, value: &str) -> bool {
            attrs.iter().any(|a| a.key == key && a.value == value)
        }

        assert!(has_attribute(
            &response.attributes,
            "action",
            "add_supported_tokens"
        ));
        assert!(has_attribute(&response.attributes, "status", "success"));

        // Check that tokens were added in deps.storage
        let config = CONFIG.load(&deps.storage).unwrap();
        assert!(config.supported_tokens.contains(&"uosmo".to_string()));
        assert!(config.supported_tokens.contains(&"uakt".to_string()));
    }

    #[test]
    fn test_execute_remove_supported_tokens() {
        let (storage, _env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let mut config = CONFIG.load(&storage).unwrap();
        // Ensure "ujuno" is in supported_tokens
        if !config.supported_tokens.contains(&"ujuno".to_string()) {
            config.supported_tokens.push("ujuno".to_string());
        }
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();

        // Ensure "admin" is in OWNERS
        let mut owners = owners;
        if !owners.contains(&Addr::unchecked("admin")) {
            owners.push(Addr::unchecked("admin"));
            OWNERS.save(&mut deps.storage, &owners).unwrap();
        }

        // Set info sender as owner
        info.sender = Addr::unchecked("admin");
        let tokens_to_remove = vec!["ujuno".to_string()];

        let result = execute_remove_supported_tokens(deps.as_mut(), info, tokens_to_remove);

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "remove_supported_tokens");
        assert_eq!(response.attributes[1].key, "status");
        assert_eq!(response.attributes[1].value, "success");

        // Check that token was removed
        let config = CONFIG.load(&deps.storage).unwrap();
        assert!(!config.supported_tokens.contains(&"ujuno".to_string()));
    }

    #[test]
    fn test_execute_add_supported_protocols() {
        let (storage, _env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy the initialized storage into deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        // Manually copy required state from storage to deps.storage
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();
        PAYMASTER_RESERVE
            .save(&mut deps.storage, &paymaster_reserve)
            .unwrap();
        let fee_structure = FEE_STRUCTURE.load(&storage).unwrap();
        FEE_STRUCTURE
            .save(&mut deps.storage, &fee_structure)
            .unwrap();
        let circuit_breaker = CIRCUIT_BREAKER.load(&storage).unwrap();
        CIRCUIT_BREAKER
            .save(&mut deps.storage, &circuit_breaker)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Set info sender as owner
        info.sender = Addr::unchecked("admin");
        let new_protocols = vec!["secret".to_string(), "terra".to_string()];

        let result = execute_add_supported_protocols(deps.as_mut(), info, new_protocols.clone());

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "add_supported_protocols");

        // Check that protocols were added using deps.storage
        let config = CONFIG.load(&deps.storage).unwrap();
        assert!(config.supported_protocols.contains(&"secret".to_string()));
        assert!(config.supported_protocols.contains(&"terra".to_string()));
    }

    #[test]
    fn test_execute_remove_supported_protocols() {
        let (storage, _env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let mut config = CONFIG.load(&storage).unwrap();
        // Ensure "osmosis" is in supported_protocols
        if !config.supported_protocols.contains(&"osmosis".to_string()) {
            config.supported_protocols.push("osmosis".to_string());
        }
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();

        // Ensure "admin" is in OWNERS
        let mut owners = owners;
        if !owners.contains(&Addr::unchecked("admin")) {
            owners.push(Addr::unchecked("admin"));
            OWNERS.save(&mut deps.storage, &owners).unwrap();
        }

        // Set info sender as owner
        info.sender = Addr::unchecked("admin");
        let protocols_to_remove = vec!["osmosis".to_string()];

        let result = execute_remove_supported_protocols(deps.as_mut(), info, protocols_to_remove);

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "remove_supported_protocols");
        assert_eq!(response.attributes[1].key, "status");
        assert_eq!(response.attributes[1].value, "success");

        // Check that protocol was removed
        let config = CONFIG.load(&deps.storage).unwrap();
        assert!(!config.supported_protocols.contains(&"osmosis".to_string()));
    }

    #[test]
    fn test_execute_update_default_timeout_height() {
        let (storage, _env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();

        // Ensure "admin" is in OWNERS
        let mut owners = owners;
        if !owners.contains(&Addr::unchecked("admin")) {
            owners.push(Addr::unchecked("admin"));
            OWNERS.save(&mut deps.storage, &owners).unwrap();
        }

        // Set info sender as owner
        info.sender = Addr::unchecked("admin");
        let new_timeout = 2000u64;

        let result = execute_update_default_timeout_height(deps.as_mut(), info, new_timeout);

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(
            response.attributes[0].value,
            "update_default_timeout_height"
        );
        assert_eq!(response.attributes[1].key, "status");
        assert_eq!(response.attributes[1].value, "success");

        // Check that timeout was updated
        let config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.default_timeout_height, new_timeout);
    }

    #[test]
    fn test_execute_add_ibc_connection() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy initial config and owners from storage to deps.storage
        let owners = OWNERS.load(&storage).unwrap();
        let mut owners = owners;
        if !owners.contains(&Addr::unchecked("admin")) {
            owners.push(Addr::unchecked("admin"));
        }
        OWNERS.save(&mut deps.storage, &owners).unwrap();

        // Set info sender as owner
        info.sender = Addr::unchecked("admin");
        let chain_id = "juno-1".to_string();
        let port = "transfer".to_string();
        let channel_id = "channel-0".to_string();

        let result = execute_add_ibc_connection(
            deps.as_mut(),
            info,
            env.clone(),
            chain_id.clone(),
            port.clone(),
            channel_id.clone(),
        );

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();

        // Check attributes without assuming order
        fn has_attribute(attrs: &[cosmwasm_std::Attribute], key: &str, value: &str) -> bool {
            attrs.iter().any(|a| a.key == key && a.value == value)
        }

        assert!(has_attribute(
            &response.attributes,
            "action",
            "add_ibc_connection"
        ));
        assert!(has_attribute(&response.attributes, "chain_id", &chain_id));
        assert!(has_attribute(&response.attributes, "status", "success"));

        // Check that connection was added in deps.storage
        let connection = IBC_CONNECTIONS.load(&deps.storage, &chain_id).unwrap();
        assert_eq!(connection.port, port);
        assert_eq!(connection.channel_id, channel_id);
        assert!(connection.is_active);
        assert_eq!(connection.last_updated, env.block.time);
    }

    #[test]
    fn test_execute_update_ibc_connection() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        let chain_id = "juno-1".to_string();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();

        // Ensure "admin" is in OWNERS
        let mut owners = owners;
        if !owners.contains(&Addr::unchecked("admin")) {
            owners.push(Addr::unchecked("admin"));
            OWNERS.save(&mut deps.storage, &owners).unwrap();
        }

        // Set up existing connection
        let connection = Connection {
            chain_id: chain_id.clone(),
            port: "transfer".to_string(),
            channel_id: "channel-0".to_string(),
            is_active: true,
            last_updated: env.block.time,
        };
        IBC_CONNECTIONS
            .save(&mut deps.storage, &chain_id, &connection)
            .unwrap();

        // Set info sender as owner
        info.sender = Addr::unchecked("admin");

        let result = execute_update_ibc_connection(
            deps.as_mut(),
            info,
            env,
            chain_id.clone(),
            Some("new_port".to_string()),
            Some("channel-1".to_string()),
            Some(false),
        );

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "update_ibc_connection");
        assert_eq!(response.attributes[1].key, "chain_id");
        assert_eq!(response.attributes[1].value, chain_id);
        assert_eq!(response.attributes[2].key, "status");
        assert_eq!(response.attributes[2].value, "success");

        // Check that connection was updated
        let updated_connection = IBC_CONNECTIONS.load(&deps.storage, &chain_id).unwrap();
        assert_eq!(updated_connection.port, "new_port".to_string());
        assert_eq!(updated_connection.channel_id, "channel-1".to_string());
        assert!(!updated_connection.is_active);
    }

    #[test]
    fn test_execute_remove_ibc_connection() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();

        let chain_id = "juno-1".to_string();

        // Set up existing connection
        let connection = Connection {
            chain_id: chain_id.clone(),
            port: "transfer".to_string(),
            channel_id: "channel-0".to_string(),
            is_active: true,
            last_updated: env.block.time,
        };
        IBC_CONNECTIONS
            .save(&mut deps.storage, &chain_id, &connection)
            .unwrap();

        // Ensure "admin" is in OWNERS
        let mut owners = owners;
        if !owners.contains(&Addr::unchecked("admin")) {
            owners.push(Addr::unchecked("admin"));
            OWNERS.save(&mut deps.storage, &owners).unwrap();
        }

        // Set info sender as owner
        info.sender = Addr::unchecked("admin");

        let result = execute_remove_ibc_connection(deps.as_mut(), info, chain_id.clone());

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "remove_ibc_connection");
        assert_eq!(response.attributes[1].key, "chain_id");
        assert_eq!(response.attributes[1].value, chain_id);
        assert_eq!(response.attributes[2].key, "status");
        assert_eq!(response.attributes[2].value, "success");

        // Check that connection was removed
        assert!(
            IBC_CONNECTIONS
                .may_load(&deps.storage, &chain_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_execute_propose_config_update() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Ensure "admin" is in OWNERS
        let mut owners = owners;
        if !owners.contains(&Addr::unchecked("admin")) {
            owners.push(Addr::unchecked("admin"));
            OWNERS.save(&mut deps.storage, &owners).unwrap();
        }

        // Set info sender as owner
        info.sender = Addr::unchecked("admin");
        let proposal_id = 1u64;

        let result = execute_propose_config_update(
            deps.as_mut(),
            env,
            info.clone(),
            proposal_id,
            Some(3),
            Some(vec!["unew".to_string()]),
            Some(vec!["new_protocol".to_string()]),
            Some(5000),
        );

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "propose_config_update");
        assert_eq!(response.attributes[1].key, "proposal_id");
        assert_eq!(response.attributes[1].value, proposal_id.to_string());
        assert_eq!(response.attributes[2].key, "proposer");
        assert_eq!(response.attributes[2].value, info.sender.to_string());

        // Check that proposal was created
        let proposal = CONFIG_PROPOSALS.load(&deps.storage, &proposal_id).unwrap();
        assert_eq!(proposal.proposer, info.sender);
        assert_eq!(proposal.threshold, Some(3));
    }

    #[test]
    fn test_execute_approve_config_proposal() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        let proposal_id = 1u64;

        // Set up existing proposal
        let proposal = ConfigProposal {
            proposal_id,
            proposer: Addr::unchecked("proposer"),
            config: UpdateConfig {
                supported_tokens: Some(vec!["unew".to_string()]),
                supported_protocols: None,
                default_timeout_height: None,
                max_intent_duration: None,
                min_intent_amount: None,
                emergency_pause: None,
                rate_limit_per_user: None,
            },
            approvals: vec![Addr::unchecked("proposer")],
            created_at: env.block.time,
            expiry: env.block.time.plus_seconds(7 * 24 * 60 * 60),
            threshold: None,
        };
        CONFIG_PROPOSALS
            .save(&mut deps.storage, &proposal_id, &proposal)
            .unwrap();

        // Ensure "admin" is in OWNERS
        let mut owners = owners;
        if !owners.contains(&Addr::unchecked("admin")) {
            owners.push(Addr::unchecked("admin"));
            OWNERS.save(&mut deps.storage, &owners).unwrap();
        }

        // Set info sender as owner
        info.sender = Addr::unchecked("admin");

        let result = execute_approve_config_proposal(deps.as_mut(), env, info.clone(), proposal_id);

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "approve_config_proposal");
        assert_eq!(response.attributes[1].key, "proposal_id");
        assert_eq!(response.attributes[1].value, proposal_id.to_string());
        assert_eq!(response.attributes[2].key, "approver");
        assert_eq!(response.attributes[2].value, info.sender.to_string());

        // Check that approval was added
        let updated_proposal = CONFIG_PROPOSALS.load(&deps.storage, &proposal_id).unwrap();
        assert!(updated_proposal.approvals.contains(&info.sender));
    }

    #[test]
    fn test_execute_execute_config_proposal() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        let proposal_id = 1u64;

        // Set threshold to 1 for easier testing
        THRESHOLD.save(&mut deps.storage, &1u32).unwrap();

        // Set up proposal with enough approvals
        let proposal = ConfigProposal {
            proposal_id,
            proposer: Addr::unchecked("admin"),
            config: UpdateConfig {
                supported_tokens: Some(vec!["unew".to_string()]),
                supported_protocols: Some(vec!["new_protocol".to_string()]),
                default_timeout_height: Some(5000),
                max_intent_duration: None,
                min_intent_amount: None,
                emergency_pause: None,
                rate_limit_per_user: None,
            },
            approvals: vec![Addr::unchecked("admin")],
            created_at: env.block.time,
            expiry: env.block.time.plus_seconds(7 * 24 * 60 * 60),
            threshold: None,
        };
        CONFIG_PROPOSALS
            .save(&mut deps.storage, &proposal_id, &proposal)
            .unwrap();

        // Ensure "admin" is in OWNERS
        let mut owners = owners;
        if !owners.contains(&Addr::unchecked("admin")) {
            owners.push(Addr::unchecked("admin"));
            OWNERS.save(&mut deps.storage, &owners).unwrap();
        }

        // Set info sender as owner
        info.sender = Addr::unchecked("admin");

        let result = execute_execute_config_proposal(deps.as_mut(), env, info, proposal_id);

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "execute_config_proposal");
        assert_eq!(response.attributes[1].key, "proposal_id");
        assert_eq!(response.attributes[1].value, proposal_id.to_string());

        // Check that config was updated
        let config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.supported_tokens, vec!["unew".to_string()]);
        assert_eq!(config.supported_protocols, vec!["new_protocol".to_string()]);
        assert_eq!(config.default_timeout_height, 5000);

        // Check that proposal was removed
        assert!(
            CONFIG_PROPOSALS
                .may_load(&deps.storage, &proposal_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_execute_initiate_recovery() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Initialize recovery state
        let recovery = Recovery {
            proposed_owner: None,
            initiated_at: None,
            guardian_approvals: vec![],
            threshold: 1,
            delay: 48 * 3600,
        };
        RECOVERY.save(&mut deps.storage, &recovery).unwrap();

        // Ensure "guardian" is in GUARDIANS
        let mut guardians = guardians;
        if !guardians.contains(&Addr::unchecked("guardian")) {
            guardians.push(Addr::unchecked("guardian"));
            GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        }

        // Set info sender as guardian
        info.sender = Addr::unchecked("guardian");
        let proposed_owner = Addr::unchecked("new_owner");

        let result =
            execute_initiate_recovery(deps.as_mut(), env, info.clone(), proposed_owner.clone());

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "initiate_recovery");
        assert_eq!(response.attributes[1].key, "proposed_owner");
        assert_eq!(response.attributes[1].value, proposed_owner.to_string());
        assert_eq!(response.attributes[2].key, "initiator");
        assert_eq!(response.attributes[2].value, info.sender.to_string());

        // Check that recovery was initiated
        let updated_recovery = RECOVERY.load(&deps.storage).unwrap();
        assert_eq!(updated_recovery.proposed_owner, Some(proposed_owner));
        assert!(updated_recovery.initiated_at.is_some());
        assert_eq!(updated_recovery.guardian_approvals, vec![info.sender]);
    }

    #[test]
    fn test_execute_approve_recovery() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let config = CONFIG.load(&storage).unwrap_or(Config {
            admin: Addr::unchecked("old_admin"),
            supported_tokens: vec![],
            supported_protocols: vec![],
            default_timeout_height: 0,
            max_intent_duration: 0,
            min_intent_amount: Uint128::zero(),
            emergency_pause: false,
            rate_limit_per_user: 0,
            fee_collector: Addr::unchecked("fee_collector"),
        });
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Set up existing recovery
        let recovery = Recovery {
            proposed_owner: Some(Addr::unchecked("new_owner")),
            initiated_at: Some(env.block.time.minus_seconds(48 * 3600 + 1)), // Past delay
            guardian_approvals: vec![],
            threshold: 1,
            delay: 48 * 3600,
        };
        RECOVERY.save(&mut deps.storage, &recovery).unwrap();

        // Ensure "guardian" is in GUARDIANS
        let mut guardians = guardians;
        if !guardians.contains(&Addr::unchecked("guardian")) {
            guardians.push(Addr::unchecked("guardian"));
            GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        }

        // Set info sender as guardian
        info.sender = Addr::unchecked("guardian");

        let result = execute_approve_recovery(deps.as_mut(), env, info.clone());

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "approve_recovery");
        assert_eq!(response.attributes[1].key, "approver");
        assert_eq!(response.attributes[1].value, info.sender.to_string());

        // Check that recovery was approved and executed
        let config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.admin, Addr::unchecked("new_owner"));
    }

    #[test]
    fn test_execute_trigger_circuit_breaker() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let circuit_breaker = CIRCUIT_BREAKER.load(&storage).unwrap();
        CIRCUIT_BREAKER
            .save(&mut deps.storage, &circuit_breaker)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Ensure "guardian" is in GUARDIANS
        let mut guardians = guardians;
        if !guardians.contains(&Addr::unchecked("guardian")) {
            guardians.push(Addr::unchecked("guardian"));
            GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        }

        // Set info sender as guardian
        info.sender = Addr::unchecked("guardian");
        let reason = "Security breach detected".to_string();

        let result =
            execute_trigger_circuit_breaker(deps.as_mut(), env, info.clone(), reason.clone());

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "trigger_circuit_breaker");
        assert_eq!(response.attributes[1].key, "reason");
        assert_eq!(response.attributes[1].value, reason);
        assert_eq!(response.attributes[2].key, "triggered_by");
        assert_eq!(response.attributes[2].value, "guardian");

        // Check that circuit breaker was triggered
        let circuit_breaker = CIRCUIT_BREAKER.load(&deps.storage).unwrap();
        assert!(circuit_breaker.is_triggered);
        assert_eq!(circuit_breaker.trigger_reason, Some(reason));
        assert_eq!(circuit_breaker.triggered_by, Some(info.sender));
    }

    #[test]
    fn test_execute_reset_circuit_breaker() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Set up triggered circuit breaker
        let circuit_breaker = CircuitBreakerState {
            is_triggered: true,
            trigger_reason: Some("Test reason".to_string()),
            triggered_at: Some(env.block.time),
            triggered_by: Some(Addr::unchecked("guardian1")),
            reset_approvals: vec![],
            reset_threshold: 1,
        };
        CIRCUIT_BREAKER
            .save(&mut deps.storage, &circuit_breaker)
            .unwrap();

        // Ensure "guardian" is in GUARDIANS
        let mut guardians = guardians;
        if !guardians.contains(&Addr::unchecked("guardian")) {
            guardians.push(Addr::unchecked("guardian"));
            GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        }

        // Set info sender as guardian
        info.sender = Addr::unchecked("guardian");

        let result = execute_reset_circuit_breaker(deps.as_mut(), env, info.clone());

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "reset_circuit_breaker");

        // Check that circuit breaker was reset
        let updated_breaker = CIRCUIT_BREAKER.load(&deps.storage).unwrap();
        assert!(!updated_breaker.is_triggered);
        assert!(updated_breaker.trigger_reason.is_none());
        assert!(updated_breaker.triggered_by.is_none());
        assert!(updated_breaker.reset_approvals.is_empty());
    }

    #[test]
    fn test_calculate_gas_price() {
        let fee_structure = FeeStructure {
            base_fee: Uint128::from(10u128),
            percentage_fee: 50,
            gas_price: Uint128::from(100u128),
            priority_multiplier: vec![
                (Priority::Low, 100),
                (Priority::Normal, 150),
                (Priority::High, 200),
                (Priority::Urgent, 300),
            ],
        };

        // Test different priorities
        assert_eq!(
            calculate_gas_price(&fee_structure, &Priority::Low),
            Uint128::from(100u128)
        );
        assert_eq!(
            calculate_gas_price(&fee_structure, &Priority::Normal),
            Uint128::from(150u128)
        );
        assert_eq!(
            calculate_gas_price(&fee_structure, &Priority::High),
            Uint128::from(200u128)
        );
        assert_eq!(
            calculate_gas_price(&fee_structure, &Priority::Urgent),
            Uint128::from(300u128)
        );
    }

    #[test]
    fn test_deduct_gas_payment_wallet_balance() {
        let (mut storage, env, info) = setup_test_env();
        let config = CONFIG.load(&storage).unwrap();
        let mut paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();

        // Set up wallet balance
        let wallet_balance = WalletBalance {
            address: info.sender.clone(),
            balances: vec![BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(1000u128),
                is_native: true,
            }],
        };
        WALLET_BALANCES
            .save(&mut storage, &info.sender, &wallet_balance)
            .unwrap();

        let gas_price = Uint128::from(100u128);
        let max_gas = Uint128::from(1_000_000u128);

        let result = deduct_gas_payment(
            &mut storage,
            &env,
            &info,
            &mut paymaster_reserve,
            &config,
            gas_price,
            max_gas,
            true,
        );

        assert!(result.is_ok());
        let gas_result = result.unwrap();
        assert_eq!(gas_result.messages.len(), 1);

        // Check that wallet balance was reduced
        let updated_wallet = WALLET_BALANCES.load(&storage, &info.sender).unwrap();
        assert_eq!(updated_wallet.balances[0].amount, Uint128::from(900u128));
    }

    #[test]
    fn test_deduct_gas_payment_insufficient_funds() {
        let (mut storage, env, mut info) = setup_test_env();

        // Ensure "uatom" is in supported_tokens
        let mut config = CONFIG.load(&storage).unwrap();
        if !config.supported_tokens.contains(&"uatom".to_string()) {
            config.supported_tokens.push("uatom".to_string());
            CONFIG.save(&mut storage, &config).unwrap();
        }

        let mut paymaster_reserve = PaymasterReserve {
            balances: vec![], // Empty paymaster reserve
        };

        // Set up wallet balance with insufficient funds
        let wallet_balance = WalletBalance {
            address: info.sender.clone(),
            balances: vec![BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(50u128), // Less than gas price
                is_native: true,
            }],
        };
        WALLET_BALANCES
            .save(&mut storage, &info.sender, &wallet_balance)
            .unwrap();

        // Ensure no transaction funds
        info.funds = vec![];

        let gas_price = Uint128::from(100u128);
        let max_gas = Uint128::from(1_000_000u128);

        let result = deduct_gas_payment(
            &mut storage,
            &env,
            &info,
            &mut paymaster_reserve,
            &config,
            gas_price,
            max_gas,
            true,
        );

        assert!(result.is_err(), "Expected error due to insufficient funds");
        assert!(matches!(
            result.unwrap_err(),
            ContractError::ValidationError(msg) if msg.contains("Insufficient funds")
        ));
    }

    #[test]
    fn test_add_cw20_transfer_msg() {
        let token_address = "cw20_token_contract";
        let recipient = Addr::unchecked("recipient");
        let amount = Uint128::from(1000u128);

        let result = add_cw20_transfer_msg(token_address, &recipient, amount);

        assert!(result.is_ok());
        let msg = result.unwrap();

        match msg {
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr,
                msg: _,
                funds,
            }) => {
                assert_eq!(contract_addr, token_address);
                assert!(funds.is_empty());
            }
            _ => panic!("Expected WasmMsg::Execute"),
        }
    }

    #[test]
    fn test_add_native_transfer_msg() {
        let denom = "uatom";
        let recipient = Addr::unchecked("recipient");
        let amount = Uint128::from(1000u128);

        let result = add_native_transfer_msg(denom, &recipient, amount);

        assert!(result.is_ok());
        let msg = result.unwrap();

        match msg {
            CosmosMsg::Bank(BankMsg::Send {
                to_address,
                amount: coins,
            }) => {
                assert_eq!(to_address, recipient.to_string());
                assert_eq!(coins.len(), 1);
                assert_eq!(coins[0].denom, denom);
                assert_eq!(coins[0].amount, amount);
            }
            _ => panic!("Expected BankMsg::Send"),
        }
    }

    #[test]
    fn test_update_health_status() {
        let (storage, env, _info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy HEALTH_STATUS from storage to deps.storage
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Test successful operation
        let result = update_health_status(deps.as_mut(), &env, true, None);
        assert!(result.is_ok());

        let health_status = HEALTH_STATUS.load(&deps.storage).unwrap();
        assert!(health_status.is_healthy);
        assert_eq!(health_status.metrics.successful_executions, 1);
        assert_eq!(health_status.metrics.failed_executions, 0);

        // Test failed operation with issue
        let issue = "Test failure".to_string();
        let result = update_health_status(deps.as_mut(), &env, false, Some(issue.clone()));
        assert!(result.is_ok());

        let health_status = HEALTH_STATUS.load(&deps.storage).unwrap();
        assert!(!health_status.is_healthy);
        assert_eq!(health_status.metrics.successful_executions, 1);
        assert_eq!(health_status.metrics.failed_executions, 1);
        assert!(health_status.issues.contains(&issue));
    }

    // Error case tests
    #[test]
    fn test_execute_create_intent_duplicate_id() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();
        PAYMASTER_RESERVE
            .save(&mut deps.storage, &paymaster_reserve)
            .unwrap();
        let fee_structure = FEE_STRUCTURE.load(&storage).unwrap();
        FEE_STRUCTURE
            .save(&mut deps.storage, &fee_structure)
            .unwrap();
        let circuit_breaker = CIRCUIT_BREAKER.load(&storage).unwrap();
        CIRCUIT_BREAKER
            .save(&mut deps.storage, &circuit_breaker)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Create and save existing intent to deps.storage
        let intent = Intent {
            id: "intent_1".to_string(),
            creator: info.sender.clone(), // "user"
            input_tokens: vec![],
            intent_type: IntentType::Swap {
                output_tokens: vec![],
            },
            executor: None,
            status: IntentStatus::Active,
            created_at: env.block.height,
            origin_chain_id: env.block.chain_id.clone(),
            target_chain_id: "juno-1".to_string(),
            timeout: env.block.height + 1000,
            tip: BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(10u128),
                is_native: true,
            },
            max_slippage: None,
            partial_fill_allowed: false,
            filled_amount: Uint128::zero(),
            execution_fee: Uint128::zero(),
            retry_count: 0,
            priority: Priority::Normal,
        };
        INTENTS
            .save(&mut deps.storage, "intent_1", &intent)
            .unwrap();

        // Set funds for input tokens, tip, and gas
        info.funds = vec![Coin {
            denom: "uatom".to_string(),
            amount: Uint128::from(1160u128), // 1000 (input) + 10 (tip) + 150 (gas)
        }];

        let input_tokens = vec![BeepCoin {
            token: "uatom".to_string(),
            amount: Uint128::from(1000u128),
            is_native: true,
        }];

        let intent_type = IntentType::Swap {
            output_tokens: vec![ExpectedToken {
                token: "ujuno".to_string(),
                is_native: true,
                amount: Uint128::from(500u128),
                target_address: None,
            }],
        };

        let tip = BeepCoin {
            token: "uatom".to_string(),
            amount: Uint128::from(10u128),
            is_native: true,
        };

        let result = execute_create_intent(
            deps.as_mut(),
            env,
            info,
            "intent_1".to_string(), // Duplicate ID
            input_tokens,
            intent_type,
            "juno-1".to_string(),
            None,
            tip,
            None,
            false,
            Priority::Normal,
            false,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContractError::ValidationError(_)
        ));
    }

    #[test]
    fn test_execute_fill_intent_invalid_status() {
        let (storage, env, mut info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();
        PAYMASTER_RESERVE
            .save(&mut deps.storage, &paymaster_reserve)
            .unwrap();
        let fee_structure = FEE_STRUCTURE.load(&storage).unwrap();
        FEE_STRUCTURE
            .save(&mut deps.storage, &fee_structure)
            .unwrap();
        let circuit_breaker = CIRCUIT_BREAKER.load(&storage).unwrap();
        CIRCUIT_BREAKER
            .save(&mut deps.storage, &circuit_breaker)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Create and save intent to deps.storage
        let intent = Intent {
            id: "intent_1".to_string(),
            creator: Addr::unchecked("creator"),
            input_tokens: vec![BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(1000u128),
                is_native: true,
            }],
            intent_type: IntentType::Swap {
                output_tokens: vec![ExpectedToken {
                    token: "ujuno".to_string(),
                    is_native: true,
                    amount: Uint128::from(500u128),
                    target_address: None,
                }],
            },
            executor: None,
            status: IntentStatus::Completed, // Cannot be filled
            created_at: env.block.height,
            origin_chain_id: env.block.chain_id.clone(),
            target_chain_id: env.block.chain_id.clone(),
            timeout: env.block.height + 1000,
            tip: BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(10u128),
                is_native: true,
            },
            max_slippage: Some(100),
            partial_fill_allowed: true,
            filled_amount: Uint128::zero(),
            execution_fee: Uint128::zero(),
            retry_count: 0,
            priority: Priority::Normal,
        };
        INTENTS
            .save(&mut deps.storage, "intent_1", &intent)
            .unwrap();

        // Set funds for gas
        info.sender = Addr::unchecked("executor");
        info.funds = vec![Coin {
            denom: "uatom".to_string(),
            amount: Uint128::from(150u128), // Gas (100 * 150 / 100)
        }];

        let chain_id = env.block.chain_id.clone();
        let result = execute_fill_intent(
            deps.as_mut(),
            env,
            info,
            "intent_1".to_string(),
            chain_id,
            intent.intent_type.clone(),
            false,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContractError::InvalidIntentStatus {}
        ));
    }

    #[test]
    fn test_execute_cancel_intent_unauthorized() {
        let (storage, env, info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();
        PAYMASTER_RESERVE
            .save(&mut deps.storage, &paymaster_reserve)
            .unwrap();
        let fee_structure = FEE_STRUCTURE.load(&storage).unwrap();
        FEE_STRUCTURE
            .save(&mut deps.storage, &fee_structure)
            .unwrap();
        let circuit_breaker = CIRCUIT_BREAKER.load(&storage).unwrap();
        CIRCUIT_BREAKER
            .save(&mut deps.storage, &circuit_breaker)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Create and save intent to deps.storage
        let intent = Intent {
            id: "intent_1".to_string(),
            creator: Addr::unchecked("different_creator"), // Different from info.sender ("user")
            input_tokens: vec![BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(1000u128),
                is_native: true,
            }],
            intent_type: IntentType::Swap {
                output_tokens: vec![ExpectedToken {
                    token: "ujuno".to_string(),
                    is_native: true,
                    amount: Uint128::from(500u128),
                    target_address: None,
                }],
            },
            executor: None,
            status: IntentStatus::Active,
            created_at: env.block.height,
            origin_chain_id: env.block.chain_id.clone(),
            target_chain_id: "juno-1".to_string(),
            timeout: env.block.height + 1000,
            tip: BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(10u128),
                is_native: true,
            },
            max_slippage: Some(100),
            partial_fill_allowed: true,
            filled_amount: Uint128::zero(),
            execution_fee: Uint128::zero(),
            retry_count: 0,
            priority: Priority::Normal,
        };
        INTENTS
            .save(&mut deps.storage, "intent_1", &intent)
            .unwrap();

        let result = execute_cancel_intent(deps.as_mut(), env, info, "intent_1".to_string());

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContractError::Unauthorized {}
        ));
    }

    #[test]
    fn test_execute_transfer_from_wallet_insufficient_balance() {
        let (storage, env, info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let paymaster_reserve = PAYMASTER_RESERVE.load(&storage).unwrap();
        PAYMASTER_RESERVE
            .save(&mut deps.storage, &paymaster_reserve)
            .unwrap();
        let fee_structure = FEE_STRUCTURE.load(&storage).unwrap();
        FEE_STRUCTURE
            .save(&mut deps.storage, &fee_structure)
            .unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Set up wallet balance with insufficient funds
        let wallet_balance = WalletBalance {
            address: info.sender.clone(),
            balances: vec![BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(100u128), // Less than requested transfer
                is_native: true,
            }],
        };
        WALLET_BALANCES
            .save(&mut deps.storage, &info.sender, &wallet_balance)
            .unwrap();

        let tokens = vec![BeepCoin {
            token: "uatom".to_string(),
            amount: Uint128::from(500u128), // More than available
            is_native: true,
        }];

        let recipient = Addr::unchecked("recipient");

        let result = execute_transfer_from_wallet(deps.as_mut(), env, info, recipient, tokens);

        assert!(result.is_err(), "Expected Err, got {:?}", result);
        assert!(matches!(
            result.unwrap_err(),
            ContractError::ValidationError(_)
        ));
    }

    #[test]
    fn test_unauthorized_operations() {
        let (storage, env, info) = setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Copy state from storage to deps.storage
        deps.querier = cosmwasm_std::testing::MockQuerier::new(&[]);
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();
        let owners = OWNERS.load(&storage).unwrap();
        OWNERS.save(&mut deps.storage, &owners).unwrap();
        let guardians = GUARDIANS.load(&storage).unwrap();
        GUARDIANS.save(&mut deps.storage, &guardians).unwrap();
        let circuit_breaker = CIRCUIT_BREAKER.load(&storage).unwrap();
        CIRCUIT_BREAKER
            .save(&mut deps.storage, &circuit_breaker)
            .unwrap();
        // Initialize RECOVERY with default value since it's not in storage
        let recovery = Recovery {
            proposed_owner: None,
            initiated_at: None,
            guardian_approvals: vec![],
            threshold: 1,
            delay: 48 * 3600,
        };
        RECOVERY.save(&mut deps.storage, &recovery).unwrap();
        let health_status = HEALTH_STATUS.load(&storage).unwrap();
        HEALTH_STATUS
            .save(&mut deps.storage, &health_status)
            .unwrap();

        // Ensure info.sender is not in OWNERS or GUARDIANS
        assert!(
            !owners.contains(&info.sender),
            "Sender should not be an owner"
        );
        assert!(
            !guardians.contains(&info.sender),
            "Sender should not be a guardian"
        );

        // Test unauthorized admin update
        let result =
            execute_update_admin(deps.as_mut(), info.clone(), Addr::unchecked("new_admin"));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContractError::Unauthorized {}
        ));

        // Test unauthorized guardian operations
        let result = execute_initiate_recovery(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            Addr::unchecked("new_owner"),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContractError::Unauthorized {}
        ));

        let result =
            execute_trigger_circuit_breaker(deps.as_mut(), env, info, "test reason".to_string());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContractError::Unauthorized {}
        ));
    }
}
