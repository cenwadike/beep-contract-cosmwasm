use cosmwasm_std::{
    Addr, CosmosMsg, Deps, DepsMut, Env, MessageInfo, StdError, StdResult, Uint128, WasmMsg,
    to_json_binary,
};
use regex::Regex;
use std::collections::HashMap;

use crate::errors::ContractError;
use crate::states::{CONFIG, ESCROW, WALLET_BALANCES};
use crate::types::{BeepCoin, Config, IntentType, WalletBalance};
use crate::{msg::InstantiateMsg, types::UpdateConfig};

pub fn validate_instantiate_msg(msg: &InstantiateMsg) -> Result<(), ContractError> {
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
    if msg.default_timeout_height < 100 {
        return Err(ContractError::ValidationError(
            "Default timeout too short".to_string(),
        ));
    }
    if msg.threshold == 0 {
        return Err(ContractError::ValidationError(
            "Threshold must be positive".to_string(),
        ));
    }
    for token in &msg.supported_tokens {
        validate_denom(token)?;
    }
    for protocol in &msg.supported_protocols {
        validate_protocol(protocol)?;
    }
    Ok(())
}

pub fn validate_update_config_msg(msg: &UpdateConfig) -> Result<(), ContractError> {
    if let Some(tokens) = &msg.supported_tokens {
        if tokens.is_empty() {
            return Err(ContractError::ValidationError(
                "Supported tokens cannot be empty".to_string(),
            ));
        }
        for token in tokens {
            validate_denom(token)?;
        }
    }
    if let Some(protocols) = &msg.supported_protocols {
        if protocols.is_empty() {
            return Err(ContractError::ValidationError(
                "Supported protocols cannot be empty".to_string(),
            ));
        }
        for protocol in protocols {
            validate_protocol(protocol)?;
        }
    }
    if let Some(default_timeout_height) = msg.default_timeout_height {
        if default_timeout_height < 100 {
            return Err(ContractError::ValidationError(
                "Default timeout too short".to_string(),
            ));
        }
    }
    if let Some(max_intent_duration) = msg.max_intent_duration {
        if max_intent_duration < 3600 {
            return Err(ContractError::ValidationError(
                "Max intent duration too short".to_string(),
            ));
        }
    }
    if let Some(min_intent_amount) = msg.min_intent_amount {
        if min_intent_amount.is_zero() {
            return Err(ContractError::ValidationError(
                "Min intent amount must be positive".to_string(),
            ));
        }
    }
    if let Some(rate_limit_per_user) = msg.rate_limit_per_user {
        if rate_limit_per_user == 0 {
            return Err(ContractError::ValidationError(
                "Rate limit per user must be positive".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn validate_denom(denom: &str) -> Result<(), ContractError> {
    let re = Regex::new(r"^[a-zA-Z0-9]{3,128}$").unwrap();
    if !re.is_match(denom) {
        return Err(ContractError::ValidationError(
            "Invalid denom format".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_protocol(protocol: &str) -> Result<(), ContractError> {
    let re = Regex::new(r"^[a-zA-Z0-9-]{3,64}$").unwrap();
    if !re.is_match(protocol) {
        return Err(ContractError::ValidationError(
            "Invalid protocol format".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_address(addr: &Addr) -> Result<(), ContractError> {
    if addr == &Addr::unchecked("") {
        return Err(ContractError::ValidationError(
            "Invalid address".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_filling(
    deps: &mut DepsMut,
    env: &Env,
    info: &MessageInfo,
    intent_id: &str,
    intent_type: &IntentType,
    use_wallet_balance: bool,
) -> Result<(Vec<BeepCoin>, Vec<CosmosMsg>), ContractError> {
    let mut tokens = ESCROW
        .load(deps.storage, (&info.sender, intent_id))
        .unwrap_or_default();
    let mut messages = vec![];
    let config = CONFIG.load(deps.storage)?;

    match intent_type {
        IntentType::Swap { output_tokens } => {
            if use_wallet_balance {
                let mut wallet_balance = WALLET_BALANCES
                    .may_load(deps.storage, &info.sender)?
                    .unwrap_or(WalletBalance {
                        address: info.sender.clone(),
                        balances: vec![],
                    });
                for token in output_tokens {
                    if !config.supported_tokens.contains(&token.token) {
                        return Err(ContractError::UnsupportedToken {});
                    }
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
                    tokens.push(BeepCoin {
                        token: token.token.clone(),
                        amount: token.amount,
                        is_native: token.is_native,
                    });
                }
                WALLET_BALANCES.save(deps.storage, &info.sender, &wallet_balance)?;
            } else {
                for token in output_tokens {
                    if !config.supported_tokens.contains(&token.token) {
                        return Err(ContractError::UnsupportedToken {});
                    }
                    if token.is_native {
                        let sent_amount = info
                            .funds
                            .iter()
                            .find(|coin| coin.denom == token.token)
                            .map(|coin| coin.amount)
                            .unwrap_or_default();
                        if sent_amount < token.amount {
                            return Err(ContractError::ValidationError(format!(
                                "Insufficient native token sent. Required: {}, Sent: {}",
                                token.amount, sent_amount
                            )));
                        }
                    } else {
                        let transfer_msgs = validate_cw20_token_payment(
                            &deps.as_ref(),
                            env,
                            info,
                            &token.token,
                            token.amount,
                        )?;
                        messages.extend(transfer_msgs);
                    }
                    tokens.push(BeepCoin {
                        token: token.token.clone(),
                        amount: token.amount,
                        is_native: token.is_native,
                    });
                }
            }
        }
        IntentType::LiquidStake { .. } | IntentType::Lend { .. } | IntentType::Generic { .. } => {
            return Err(ContractError::Unimplemented {});
        }
    }

    Ok((tokens, messages))
}

pub fn validate_native_token_payment(
    info: &MessageInfo,
    denom: &str,
    required_amount: Uint128,
) -> StdResult<()> {
    // Find the coin with matching denom in the sent funds
    let sent_amount = info
        .funds
        .iter()
        .find(|coin| coin.denom == denom)
        .map(|coin| coin.amount)
        .unwrap_or_default();

    // Check if sent amount matches required amount
    if sent_amount < required_amount {
        return Err(StdError::generic_err(format!(
            "Insufficient native token sent. Required: {}, Sent: {}",
            required_amount, sent_amount
        )));
    }

    // Check if excess amount was sent
    if sent_amount > required_amount {
        return Err(StdError::generic_err(format!(
            "Excess native token sent. Required: {}, Sent: {}",
            required_amount, sent_amount
        )));
    }

    Ok(())
}

pub fn validate_cw20_token_payment(
    deps: &Deps,
    env: &Env,
    info: &MessageInfo,
    token_address: &str,
    required_amount: Uint128,
) -> StdResult<Vec<CosmosMsg>> {
    // Query token balance
    let balance: cw20::BalanceResponse = deps.querier.query_wasm_smart(
        token_address,
        &cw20::Cw20QueryMsg::Balance {
            address: info.sender.to_string(),
        },
    )?;

    // Check if user has sufficient balance
    if balance.balance < required_amount {
        return Err(StdError::generic_err(format!(
            "Insufficient CW20 token balance. Required: {}, Balance: {}",
            required_amount, balance.balance
        )));
    }

    // Query allowance
    let allowance: cw20::AllowanceResponse = deps.querier.query_wasm_smart(
        token_address,
        &cw20::Cw20QueryMsg::Allowance {
            owner: info.sender.to_string(),
            spender: env.contract.address.to_string(),
        },
    )?;

    // Check if contract has sufficient allowance
    if allowance.allowance < required_amount {
        return Err(StdError::generic_err(format!(
            "Insufficient CW20 token allowance. Required: {}, Allowance: {}",
            required_amount, allowance.allowance
        )));
    }

    let mut messages: Vec<CosmosMsg> = vec![];

    // transfer out the funds
    messages.push(
        WasmMsg::Execute {
            contract_addr: token_address.to_string(),
            msg: to_json_binary(&cw20::Cw20ExecuteMsg::TransferFrom {
                owner: info.sender.to_string(),
                recipient: env.contract.address.to_string(),
                amount: required_amount,
            })?,
            funds: vec![],
        }
        .into(),
    );

    Ok(messages)
}

pub fn validate_intent_type(
    intent_type: &IntentType,
    config: &Config,
) -> Result<(), ContractError> {
    match intent_type {
        IntentType::Swap { output_tokens } => {
            for token in output_tokens {
                if !config.supported_tokens.contains(&token.token) {
                    return Err(ContractError::UnsupportedToken {});
                }
            }
        }
        _ => return Err(ContractError::Unimplemented {}),
    }
    Ok(())
}

pub fn validate_tokens(
    deps: &DepsMut,
    env: &Env,
    info: &MessageInfo,
    input_tokens: &[BeepCoin],
) -> Result<Vec<CosmosMsg>, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let mut msg: Vec<CosmosMsg> = vec![];

    // Aggregate amounts by token denomination
    let mut token_sums: HashMap<String, (Uint128, bool)> = HashMap::new();
    for token in input_tokens {
        if !config.supported_tokens.contains(&token.token) {
            return Err(ContractError::UnsupportedToken {});
        }
        let entry = token_sums
            .entry(token.token.clone())
            .or_insert((Uint128::zero(), token.is_native));
        if entry.1 != token.is_native {
            return Err(ContractError::ValidationError(format!(
                "Mixed native and non-native tokens for {}",
                token.token
            )));
        }
        entry.0 += token.amount;
    }

    // Validate aggregated amounts
    for (denom, (total_amount, is_native)) in token_sums {
        if is_native {
            validate_native_token_payment(info, &denom, total_amount)?;
        } else {
            let transfer_from_msg =
                validate_cw20_token_payment(&deps.as_ref(), env, info, &denom, total_amount)?;
            msg = [msg.clone(), transfer_from_msg].concat();
        }
    }

    Ok(msg)
}
