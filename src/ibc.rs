use cosmwasm_std::{
    Addr, BankMsg, Coin, CosmosMsg, DepsMut, Env, IbcBasicResponse, IbcChannel, IbcChannelCloseMsg,
    IbcChannelConnectMsg, IbcChannelOpenMsg, IbcChannelOpenResponse, IbcOrder, IbcPacketAckMsg,
    IbcPacketReceiveMsg, IbcPacketTimeoutMsg, IbcReceiveResponse, Never, StdAck, StdError,
    StdResult, Uint128, WasmMsg, entry_point, from_json, to_json_binary,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::errors::ContractError;
use crate::msg::IbcExecuteMsg;
use crate::states::{ESCROW, IBC_CONNECTIONS, INTENTS};
use crate::types::{IntentStatus, IntentType};

pub const IBC_VERSION: &str = "beep-1";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum IbcAcknowledgement {
    Success(String), // Intent ID
    Error(String),   // Error message
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_channel_open(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelOpenMsg,
) -> Result<IbcChannelOpenResponse, ContractError> {
    validate_order_and_version(msg.channel(), msg.counterparty_version())?;
    Ok(None)
}

pub fn validate_order_and_version(
    channel: &IbcChannel,
    counterparty_version: Option<&str>,
) -> Result<(), ContractError> {
    if channel.order != IbcOrder::Unordered {
        return Err(ContractError::Std(StdError::generic_err(
            "Only supports unordered channels",
        )));
    }
    if channel.version != IBC_VERSION {
        return Err(ContractError::Std(StdError::generic_err(format!(
            "Invalid IBC version. Actual: {}, Expected: {}",
            channel.version, IBC_VERSION
        ))));
    }
    if let Some(version) = counterparty_version {
        if version != IBC_VERSION {
            return Err(ContractError::Std(StdError::generic_err(format!(
                "Invalid counterparty version. Actual: {}, Expected: {}",
                version, IBC_VERSION
            ))));
        }
    }
    Ok(())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_channel_connect(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelConnectMsg,
) -> Result<IbcBasicResponse, ContractError> {
    validate_order_and_version(msg.channel(), msg.counterparty_version())?;
    let channel_id = msg.channel().endpoint.channel_id.clone();
    Ok(IbcBasicResponse::new()
        .add_attribute("action", "ibc_channel_connect")
        .add_attribute("channel_id", channel_id))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_channel_close(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelCloseMsg,
) -> Result<IbcBasicResponse, ContractError> {
    let channel_id = msg.channel().endpoint.channel_id.clone();
    Ok(IbcBasicResponse::new()
        .add_attribute("action", "ibc_channel_close")
        .add_attribute("channel_id", channel_id))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_packet_receive(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, Never> {
    match process_received_intent(deps, env, msg) {
        Ok(response) => Ok(response),
        Err(error) => Ok(
            IbcReceiveResponse::new(StdAck::error(format!("{:?}", error)))
                .add_attribute("action", "ibc_packet_receive")
                .add_attribute("error", error.to_string()),
        ),
    }
}

pub fn process_received_intent(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, ContractError> {
    let channel_id = msg.packet.dest.channel_id.clone();
    let packet_data: IbcExecuteMsg = from_json(&msg.packet.data)?;
    match packet_data {
        IbcExecuteMsg::FillIntent {
            intent_id,
            executor,
        } => execute_ibc_fill_intent(deps, env, channel_id, intent_id, executor),
    }
}

fn execute_ibc_fill_intent(
    deps: DepsMut,
    _env: Env,
    channel_id: String,
    intent_id: String,
    executor: Addr,
) -> Result<IbcReceiveResponse, ContractError> {
    let mut intent = INTENTS.load(deps.storage, &intent_id)?;
    if !intent.can_be_filled() {
        return Err(ContractError::InvalidIntentStatus {});
    }
    if intent.executor.is_some() && intent.executor != Some(executor.clone()) {
        return Err(ContractError::Unauthorized {});
    }
    let connection = IBC_CONNECTIONS.load(deps.storage, &intent.target_chain_id)?;
    if connection.channel_id != channel_id {
        return Err(ContractError::ValidationError(
            "Invalid channel for target chain".to_string(),
        ));
    }
    if intent.origin_chain_id == intent.target_chain_id {
        return Err(ContractError::ValidationError(
            "Same-chain intent should not be processed via IBC".to_string(),
        ));
    }
    let mut messages: Vec<CosmosMsg> = vec![];
    for token in intent.input_tokens.iter() {
        if token.is_native {
            messages.push(add_native_transfer_msg(
                &token.token,
                &executor,
                token.amount,
            )?);
        } else {
            messages.push(add_cw20_transfer_msg(
                &token.token,
                &executor,
                token.amount,
            )?);
        }
    }
    if intent.tip.is_native {
        messages.push(add_native_transfer_msg(
            &intent.tip.token,
            &executor,
            intent.tip.amount,
        )?);
    } else {
        messages.push(add_cw20_transfer_msg(
            &intent.tip.token,
            &executor,
            intent.tip.amount,
        )?);
    }
    intent.status = IntentStatus::Pending;
    intent.executor = Some(executor.clone());
    INTENTS.save(deps.storage, &intent_id, &intent)?;
    ESCROW.remove(deps.storage, (&intent.creator, &intent_id));
    Ok(
        IbcReceiveResponse::new(StdAck::success(to_json_binary(&intent_id)?))
            .add_messages(messages)
            .add_attribute("action", "execute_cross_chain_fill_intent")
            .add_attribute("intent_id", intent_id)
            .add_attribute("executor", executor.to_string())
            .add_attribute("channel_id", channel_id),
    )
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_packet_ack(
    deps: DepsMut,
    _env: Env,
    ack: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    let ack_data: IbcAcknowledgement = from_json(&ack.acknowledgement.data)?;
    let mut messages: Vec<CosmosMsg> = vec![];
    match ack_data {
        IbcAcknowledgement::Success(intent_id) => {
            let mut intent = INTENTS.load(deps.storage, &intent_id)?;
            if !matches!(intent.status, IntentStatus::Pending) {
                return Err(ContractError::InvalidIntentStatus {});
            }
            intent.status = IntentStatus::Completed;
            INTENTS.save(deps.storage, &intent_id, &intent)?;
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
                }
                IntentType::LiquidStake { .. }
                | IntentType::Lend { .. }
                | IntentType::Generic { .. } => {
                    return Err(ContractError::Unimplemented {});
                }
            }
            if let Some(executor) = intent.executor.clone() {
                ESCROW.remove(deps.storage, (&executor, &intent_id));
            }
            Ok(IbcBasicResponse::new()
                .add_messages(messages)
                .add_attribute("action", "ibc_packet_ack")
                .add_attribute("success", "true")
                .add_attribute("intent_id", intent_id))
        }
        IbcAcknowledgement::Error(err) => {
            let packet_data: IbcExecuteMsg = from_json(&ack.original_packet.data)?;
            let intent_id = match packet_data {
                IbcExecuteMsg::FillIntent { intent_id, .. } => intent_id,
            };
            let mut intent = INTENTS.load(deps.storage, &intent_id)?;
            intent.status = IntentStatus::Failed {
                reason: err.clone(),
            };
            intent.retry_count += 1;
            INTENTS.save(deps.storage, &intent_id, &intent)?;
            if let Some(executor) = intent.executor.clone() {
                let tokens = ESCROW.load(deps.storage, (&executor, &intent_id))?;
                for token in tokens {
                    if token.is_native {
                        messages.push(add_native_transfer_msg(
                            &token.token,
                            &executor,
                            token.amount,
                        )?);
                    } else {
                        messages.push(add_cw20_transfer_msg(
                            &token.token,
                            &executor,
                            token.amount,
                        )?);
                    }
                }
                ESCROW.remove(deps.storage, (&executor, &intent_id));
            }
            Ok(IbcBasicResponse::new()
                .add_messages(messages)
                .add_attribute("action", "ibc_packet_ack")
                .add_attribute("success", "false")
                .add_attribute("intent_id", intent_id)
                .add_attribute("error", err))
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_packet_timeout(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    let packet_data: IbcExecuteMsg = from_json(&msg.packet.data)?;
    let mut messages: Vec<CosmosMsg> = vec![];
    match packet_data {
        IbcExecuteMsg::FillIntent {
            intent_id,
            executor,
        } => {
            let mut intent = INTENTS.load(deps.storage, &intent_id)?;
            intent.status = IntentStatus::Failed {
                reason: "Packet timeout".to_string(),
            };
            intent.retry_count += 1;
            INTENTS.save(deps.storage, &intent_id, &intent)?;
            let tokens = ESCROW.load(deps.storage, (&executor, &intent_id))?;
            for token in tokens {
                if token.is_native {
                    messages.push(add_native_transfer_msg(
                        &token.token,
                        &executor,
                        token.amount,
                    )?);
                } else {
                    messages.push(add_cw20_transfer_msg(
                        &token.token,
                        &executor,
                        token.amount,
                    )?);
                }
            }
            ESCROW.remove(deps.storage, (&executor, &intent_id));
            Ok(IbcBasicResponse::new()
                .add_messages(messages)
                .add_attribute("action", "ibc_packet_timeout")
                .add_attribute("intent_id", intent_id)
                .add_attribute("executor", executor.to_string()))
        }
    }
}

pub fn add_cw20_transfer_msg(
    token_address: &str,
    to: &Addr,
    amount: Uint128,
) -> StdResult<CosmosMsg> {
    Ok(WasmMsg::Execute {
        contract_addr: token_address.to_string(),
        msg: to_json_binary(&cw20::Cw20ExecuteMsg::Transfer {
            recipient: to.to_string(),
            amount,
        })?,
        funds: vec![],
    }
    .into())
}

pub fn add_native_transfer_msg(denom: &str, to: &Addr, amount: Uint128) -> StdResult<CosmosMsg> {
    Ok(BankMsg::Send {
        to_address: to.to_string(),
        amount: vec![Coin {
            denom: denom.to_string(),
            amount,
        }],
    }
    .into())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::IbcExecuteMsg;
    use crate::types::{
        BeepCoin, Connection, ExpectedToken, Intent, IntentStatus, IntentType, Priority,
    };
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        Addr, IbcChannel, IbcChannelCloseMsg, IbcChannelConnectMsg, IbcChannelOpenMsg, IbcEndpoint,
        IbcOrder, IbcPacket, IbcPacketAckMsg, IbcPacketReceiveMsg, IbcPacketTimeoutMsg, Timestamp,
        from_json, to_json_binary,
    };

    fn mock_ibc_channel(channel_id: &str) -> IbcChannel {
        IbcChannel::new(
            IbcEndpoint {
                port_id: "wasm.contract".to_string(),
                channel_id: channel_id.to_string(),
            },
            IbcEndpoint {
                port_id: "wasm.contract".to_string(),
                channel_id: "channel-1".to_string(),
            },
            IbcOrder::Unordered,
            IBC_VERSION,
            "connection-1",
        )
    }

    fn mock_intent() -> Intent {
        Intent {
            id: "test_intent_1".to_string(),
            creator: Addr::unchecked("creator"),
            origin_chain_id: "chain-1".to_string(),
            target_chain_id: "chain-2".to_string(),
            intent_type: IntentType::Swap {
                output_tokens: vec![ExpectedToken {
                    token: "uosmo".to_string(),
                    amount: Uint128::from(1000u128),
                    is_native: true,
                    target_address: None,
                }],
            },
            input_tokens: vec![BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(500u128),
                is_native: true,
            }],
            tip: BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(10u128),
                is_native: true,
            },
            status: IntentStatus::Active,
            executor: None,
            created_at: 1000,
            timeout: 2000,
            max_slippage: Some(100),
            partial_fill_allowed: false,
            filled_amount: Uint128::zero(),
            execution_fee: Uint128::from(5u128),
            retry_count: 0,
            priority: Priority::Normal,
        }
    }

    #[test]
    fn test_ibc_channel_open() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let channel = mock_ibc_channel("channel-0");

        let msg = IbcChannelOpenMsg::new_init(channel.clone());

        let res = ibc_channel_open(deps.as_mut(), env, msg).unwrap();
        assert_eq!(res, None);
    }

    #[test]
    fn test_ibc_channel_open_invalid_version() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let mut channel = mock_ibc_channel("channel-0");
        channel.version = "invalid-version".to_string();

        let msg = IbcChannelOpenMsg::new_init(channel);

        let err = ibc_channel_open(deps.as_mut(), env, msg).unwrap_err();
        assert!(matches!(err, ContractError::Std(_)));
    }

    #[test]
    fn test_validate_order_and_version_success() {
        let channel = mock_ibc_channel("channel-0");
        let result = validate_order_and_version(&channel, Some(IBC_VERSION));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_order_and_version_wrong_order() {
        let mut channel = mock_ibc_channel("channel-0");
        channel.order = IbcOrder::Ordered;

        let result = validate_order_and_version(&channel, Some(IBC_VERSION));
        assert!(result.is_err());
    }

    #[test]
    fn test_ibc_channel_connect() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let channel = mock_ibc_channel("channel-0");

        let msg = IbcChannelConnectMsg::new_ack(channel, IBC_VERSION.to_string());

        let res = ibc_channel_connect(deps.as_mut(), env, msg).unwrap();
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "ibc_channel_connect");
        assert_eq!(res.attributes[1].key, "channel_id");
        assert_eq!(res.attributes[1].value, "channel-0");
    }

    #[test]
    fn test_ibc_channel_close() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let channel = mock_ibc_channel("channel-0");

        let msg = IbcChannelCloseMsg::new_init(channel);

        let res = ibc_channel_close(deps.as_mut(), env, msg).unwrap();
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "ibc_channel_close");
        assert_eq!(res.attributes[1].key, "channel_id");
        assert_eq!(res.attributes[1].value, "channel-0");
    }

    #[test]
    fn test_ibc_packet_receive_success() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // Setup test data
        let intent = mock_intent();
        let executor = deps.api.addr_make("executor");
        let connection = Connection {
            chain_id: "chain-2".to_string(),
            channel_id: "channel-0".to_string(),
            port: "wasm.contract".to_string(),
            is_active: true,
            last_updated: Timestamp::from_seconds(1000),
        };

        // Store test data
        INTENTS
            .save(deps.as_mut().storage, &intent.id, &intent)
            .unwrap();
        IBC_CONNECTIONS
            .save(deps.as_mut().storage, &intent.target_chain_id, &connection)
            .unwrap();

        let packet_data = IbcExecuteMsg::FillIntent {
            intent_id: intent.id.clone(),
            executor: executor.clone(),
        };

        let packet = IbcPacket::new(
            to_json_binary(&packet_data).unwrap(),
            IbcEndpoint {
                port_id: "wasm.contract".to_string(),
                channel_id: "channel-1".to_string(),
            },
            IbcEndpoint {
                port_id: "wasm.contract".to_string(),
                channel_id: "channel-0".to_string(),
            },
            1,
            Timestamp::from_seconds(2000).into(),
        );

        let relayer = Addr::unchecked("relayer"); // or use a mock relayer address as needed
        let msg = IbcPacketReceiveMsg::new(packet, relayer);

        let res = ibc_packet_receive(deps.as_mut(), env, msg).unwrap();
        assert!(res.acknowledgement.is_some());
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "execute_cross_chain_fill_intent");
    }

    #[test]
    fn test_process_received_intent_invalid_status() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // Setup test data with completed intent
        let mut intent = mock_intent();
        intent.status = IntentStatus::Completed;
        let executor = deps.api.addr_make("executor");

        INTENTS
            .save(deps.as_mut().storage, &intent.id, &intent)
            .unwrap();

        let packet_data = IbcExecuteMsg::FillIntent {
            intent_id: intent.id.clone(),
            executor: executor.clone(),
        };

        let packet = IbcPacket::new(
            to_json_binary(&packet_data).unwrap(),
            IbcEndpoint {
                port_id: "wasm.contract".to_string(),
                channel_id: "channel-1".to_string(),
            },
            IbcEndpoint {
                port_id: "wasm.contract".to_string(),
                channel_id: "channel-0".to_string(),
            },
            1,
            Timestamp::from_seconds(2000).into(),
        );

        let relayer = Addr::unchecked("relayer"); // or use a mock relayer address as needed
        let msg = IbcPacketReceiveMsg::new(packet, relayer);

        let err = process_received_intent(deps.as_mut(), env, msg).unwrap_err();
        assert!(matches!(err, ContractError::InvalidIntentStatus {}));
    }

    #[test]
    fn test_ibc_packet_ack_success() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // Setup test data with pending intent
        let mut intent = mock_intent();
        intent.status = IntentStatus::Pending;
        intent.executor = Some(deps.api.addr_make("executor"));

        INTENTS
            .save(deps.as_mut().storage, &intent.id, &intent)
            .unwrap();

        // Create the custom acknowledgment directly
        let ack_data = IbcAcknowledgement::Success(intent.id.clone());
        let ack_binary = to_json_binary(&ack_data).unwrap();
        let ack = cosmwasm_std::IbcAcknowledgement::new(ack_binary);

        let packet_data = IbcExecuteMsg::FillIntent {
            intent_id: intent.id.clone(),
            executor: intent.executor.clone().unwrap(),
        };

        let original_packet = IbcPacket::new(
            to_json_binary(&packet_data).unwrap(),
            IbcEndpoint {
                port_id: "wasm.contract".to_string(),
                channel_id: "channel-0".to_string(),
            },
            IbcEndpoint {
                port_id: "wasm.contract".to_string(),
                channel_id: "channel-1".to_string(),
            },
            1,
            Timestamp::from_seconds(2000).into(),
        );

        let relayer = Addr::unchecked("relayer");
        let msg = IbcPacketAckMsg::new(ack, original_packet, relayer);

        let res = ibc_packet_ack(deps.as_mut(), env, msg).unwrap();
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "ibc_packet_ack");
        assert_eq!(res.attributes[1].key, "success");
        assert_eq!(res.attributes[1].value, "true");
    }

    #[test]
    fn test_ibc_packet_ack_error() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // Setup test data
        let intent = mock_intent();
        let executor = deps.api.addr_make("executor");
        let tokens = vec![BeepCoin {
            token: "uatom".to_string(),
            amount: Uint128::from(500u128),
            is_native: true,
        }];

        INTENTS
            .save(deps.as_mut().storage, &intent.id, &intent)
            .unwrap();
        ESCROW
            .save(deps.as_mut().storage, (&executor, &intent.id), &tokens)
            .unwrap();

        // Create the custom acknowledgment directly
        let ack_data = IbcAcknowledgement::Error("Test error".to_string());
        let ack_binary = to_json_binary(&ack_data).unwrap();
        let ack = cosmwasm_std::IbcAcknowledgement::new(ack_binary);

        let packet_data = IbcExecuteMsg::FillIntent {
            intent_id: intent.id.clone(),
            executor: executor.clone(),
        };

        let original_packet = IbcPacket::new(
            to_json_binary(&packet_data).unwrap(),
            IbcEndpoint {
                port_id: "wasm.contract".to_string(),
                channel_id: "channel-0".to_string(),
            },
            IbcEndpoint {
                port_id: "wasm.contract".to_string(),
                channel_id: "channel-1".to_string(),
            },
            1,
            Timestamp::from_seconds(2000).into(),
        );

        let relayer = Addr::unchecked("relayer");
        let msg = IbcPacketAckMsg::new(ack, original_packet, relayer);

        let res = ibc_packet_ack(deps.as_mut(), env, msg).unwrap();
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "ibc_packet_ack");
        assert_eq!(res.attributes[1].key, "success");
        assert_eq!(res.attributes[1].value, "false");
        assert_eq!(res.attributes[3].key, "error");
        assert_eq!(res.attributes[3].value, "Test error");
    }

    #[test]
    fn test_ibc_packet_timeout() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // Setup test data
        let intent = mock_intent();
        let executor = deps.api.addr_make("executor");
        let tokens = vec![BeepCoin {
            token: "uatom".to_string(),
            amount: Uint128::from(500u128),
            is_native: true,
        }];

        INTENTS
            .save(deps.as_mut().storage, &intent.id, &intent)
            .unwrap();
        ESCROW
            .save(deps.as_mut().storage, (&executor, &intent.id), &tokens)
            .unwrap();

        let packet_data = IbcExecuteMsg::FillIntent {
            intent_id: intent.id.clone(),
            executor: executor.clone(),
        };

        let packet = IbcPacket::new(
            to_json_binary(&packet_data).unwrap(),
            IbcEndpoint {
                port_id: "wasm.contract".to_string(),
                channel_id: "channel-0".to_string(),
            },
            IbcEndpoint {
                port_id: "wasm.contract".to_string(),
                channel_id: "channel-1".to_string(),
            },
            1,
            Timestamp::from_seconds(1000).into(),
        );

        let relayer = Addr::unchecked("relayer"); // or use a mock relayer address as needed
        let msg = IbcPacketTimeoutMsg::new(packet, relayer);

        let res = ibc_packet_timeout(deps.as_mut(), env, msg).unwrap();
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "ibc_packet_timeout");
        assert_eq!(res.attributes[1].key, "intent_id");
        assert_eq!(res.attributes[1].value, intent.id);
        assert_eq!(res.attributes[2].key, "executor");
        assert_eq!(res.attributes[2].value, executor.to_string());
    }

    #[test]
    fn test_add_cw20_transfer_msg() {
        let token_address = "contract123";
        let recipient = Addr::unchecked("recipient");
        let amount = Uint128::from(1000u128);

        let msg = add_cw20_transfer_msg(token_address, &recipient, amount).unwrap();

        match msg {
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr,
                msg,
                funds,
            }) => {
                assert_eq!(contract_addr, token_address);
                assert!(funds.is_empty());

                let cw20_msg: cw20::Cw20ExecuteMsg = from_json(&msg).unwrap();
                match cw20_msg {
                    cw20::Cw20ExecuteMsg::Transfer {
                        recipient: rcpt,
                        amount: amt,
                    } => {
                        assert_eq!(rcpt, recipient.to_string());
                        assert_eq!(amt, amount);
                    }
                    _ => panic!("Wrong message type"),
                }
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_add_native_transfer_msg() {
        let denom = "uatom";
        let recipient = Addr::unchecked("recipient");
        let amount = Uint128::from(1000u128);

        let msg = add_native_transfer_msg(denom, &recipient, amount).unwrap();

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
            _ => panic!("Wrong message type"),
        }
    }
}
