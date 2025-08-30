use cosmwasm_std::{Addr, Binary, Deps, Env, StdResult, Uint128, to_json_binary};
use cw_storage_plus::Bound;

use crate::msg::{
    ConfigProposalResponse, ConfigResponse, ConnectionResponse, HealthStatusResponse,
    IntentResponse, IntentsResponse, PaymasterReserveResponse, QueryMsg, UserNonceResponse,
    UserRecoveryResponse, WalletBalanceResponse,
};
use crate::states::{
    CONFIG, CONFIG_PROPOSALS, HEALTH_STATUS, IBC_CONNECTIONS, INTENTS, PAYMASTER_RESERVE,
    USER_NONCE, USER_RECOVERIES, WALLET_BALANCES,
};
use crate::types::{HealthMetrics, HealthStatus, Intent, UserRecovery, WalletBalance};

pub fn handle_query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => to_json_binary(&query_config(deps)?),
        QueryMsg::GetConnection { chain_id } => to_json_binary(&query_connection(deps, chain_id)?),
        QueryMsg::GetIntent { id } => to_json_binary(&query_intent(deps, id)?),
        QueryMsg::ListIntents { start_after, limit } => {
            to_json_binary(&query_list_intents(deps, start_after, limit)?)
        }
        QueryMsg::GetUserNonce { address } => to_json_binary(&query_get_user_nonce(deps, address)?),
        QueryMsg::GetConfigProposal { proposal_id } => {
            to_json_binary(&query_config_proposal(deps, proposal_id)?)
        }
        QueryMsg::GetHealthStatus {} => to_json_binary(&query_health_status(deps, env)?),
        QueryMsg::GetWalletBalance { address } => {
            to_json_binary(&query_wallet_balance(deps, address)?)
        }
        QueryMsg::GetPaymasterReserve {} => to_json_binary(&query_paymaster_reserve(deps)?),
        QueryMsg::GetUserRecovery { user } => to_json_binary(&query_user_recovery(deps, user)?),
    }
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(ConfigResponse {
        admin: config.admin,
        supported_tokens: config.supported_tokens,
        supported_protocols: config.supported_protocols,
        default_timeout_height: config.default_timeout_height,
        fee_collector: config.fee_collector,
        max_intent_duration: config.max_intent_duration,
        min_intent_amount: config.min_intent_amount,
        emergency_pause: config.emergency_pause,
        rate_limit_per_user: config.rate_limit_per_user,
    })
}

fn query_connection(deps: Deps, chain_id: String) -> StdResult<ConnectionResponse> {
    let connection = IBC_CONNECTIONS.load(deps.storage, &chain_id)?;
    Ok(ConnectionResponse {
        chain_id: connection.chain_id,
        port: connection.port,
        channel_id: connection.channel_id,
    })
}

fn query_intent(deps: Deps, id: String) -> StdResult<IntentResponse> {
    let intent = INTENTS.load(deps.storage, &id)?;
    Ok(IntentResponse { intent })
}

fn query_list_intents(
    deps: Deps,
    start_from: Option<String>,
    limit: Option<u32>,
) -> StdResult<IntentsResponse> {
    let start = start_from.unwrap();
    let limit = limit.unwrap_or(100) as usize;

    let intents: StdResult<Vec<Intent>> = INTENTS
        .range(
            deps.storage,
            Some(Bound::inclusive(&*start)),
            None,
            cosmwasm_std::Order::Ascending,
        )
        .take(limit)
        .map(|item| item.map(|(_, intent)| intent))
        .collect();

    Ok(IntentsResponse { intents: intents? })
}

fn query_get_user_nonce(deps: Deps, address: Addr) -> StdResult<UserNonceResponse> {
    let nonce = USER_NONCE
        .may_load(deps.storage, &address)?
        .unwrap_or(0u128);
    Ok(UserNonceResponse { nonce })
}

fn query_config_proposal(deps: Deps, proposal_id: u64) -> StdResult<ConfigProposalResponse> {
    let proposal = CONFIG_PROPOSALS.load(deps.storage, &proposal_id)?;
    Ok(ConfigProposalResponse {
        proposer: proposal.proposer,
        config: proposal.config,
        approvals: proposal.approvals,
        created_at: proposal.created_at,
        expiry: proposal.expiry,
        threshold: proposal.threshold,
        proposal_id: proposal_id,
    })
}

fn query_health_status(deps: Deps, env: Env) -> StdResult<HealthStatusResponse> {
    let health = HEALTH_STATUS
        .may_load(deps.storage)?
        .unwrap_or(HealthStatus {
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
        });
    Ok(HealthStatusResponse {
        is_healthy: health.is_healthy,
        last_check: health.last_check,
        last_check_height: health.last_check_height,
        issues: health.issues,
        metrics: health.metrics,
    })
}

fn query_wallet_balance(deps: Deps, address: Addr) -> StdResult<WalletBalanceResponse> {
    let balance = WALLET_BALANCES
        .may_load(deps.storage, &address)?
        .unwrap_or(WalletBalance {
            address: address.clone(),
            balances: vec![],
        });
    Ok(WalletBalanceResponse {
        address: balance.address,
        balances: balance.balances,
    })
}

fn query_paymaster_reserve(deps: Deps) -> StdResult<PaymasterReserveResponse> {
    let reserve = PAYMASTER_RESERVE.load(deps.storage)?;
    Ok(PaymasterReserveResponse {
        balances: reserve.balances,
    })
}

fn query_user_recovery(deps: Deps, user: Addr) -> StdResult<UserRecoveryResponse> {
    let recovery = USER_RECOVERIES
        .may_load(deps.storage, &user)?
        .unwrap_or(UserRecovery {
            user: user.clone(),
            new_address: None,
            initiated_at: None,
            guardian_approvals: vec![],
            threshold: 0,
            delay: 48 * 3600,
        });
    Ok(UserRecoveryResponse {
        user,
        new_address: recovery.new_address,
        initiated_at: recovery.initiated_at,
        guardian_approvals: recovery.guardian_approvals,
        threshold: recovery.threshold,
        delay: recovery.delay,
    })
}

pub mod test {
    use super::*;
    use crate::states::{CIRCUIT_BREAKER, FEE_STRUCTURE, GUARDIANS, OWNERS};
    use crate::types::*;
    #[allow(unused_imports)]
    use cosmwasm_std::{Addr, Timestamp, Uint128, coins};
    use cosmwasm_std::{MessageInfo, testing::*};

    fn _setup_test_env() -> (cosmwasm_std::testing::MockStorage, Env, MessageInfo) {
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
    fn test_query_config() {
        let (storage, _env, _info) = _setup_test_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Load initial config from setup into deps.storage
        let config = CONFIG.load(&storage).unwrap();
        CONFIG.save(&mut deps.storage, &config).unwrap();

        // Call the query function
        let result = query_config(deps.as_ref());

        // Assert the result is OK
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();

        // Validate each field
        assert_eq!(response.admin, config.admin);
        assert_eq!(response.supported_tokens, config.supported_tokens);
        assert_eq!(response.supported_protocols, config.supported_protocols);
        assert_eq!(
            response.default_timeout_height,
            config.default_timeout_height
        );
        assert_eq!(response.fee_collector, config.fee_collector);
        assert_eq!(response.max_intent_duration, config.max_intent_duration);
        assert_eq!(response.min_intent_amount, config.min_intent_amount);
        assert_eq!(response.emergency_pause, config.emergency_pause);
        assert_eq!(response.rate_limit_per_user, config.rate_limit_per_user);
    }

    #[test]
    fn test_query_connection() {
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Define test data
        let chain_id = "juno-1".to_string();
        let port = "transfer".to_string();
        let channel_id = "channel-0".to_string();

        // Save a mock IBC connection into storage
        let connection = Connection {
            chain_id: chain_id.clone(),
            port: port.clone(),
            channel_id: channel_id.clone(),
            is_active: true,
            last_updated: cosmwasm_std::Timestamp::from_seconds(1_000_000),
        };
        IBC_CONNECTIONS
            .save(&mut deps.storage, &chain_id, &connection)
            .unwrap();

        // Query the connection
        let result = query_connection(deps.as_ref(), chain_id.clone());

        // Assert success
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();

        // Validate fields
        assert_eq!(response.chain_id, chain_id);
        assert_eq!(response.port, port);
        assert_eq!(response.channel_id, channel_id);
    }

    #[test]
    fn test_query_intent() {
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Define test intent data
        let intent_id = "intent-123".to_string();
        let intent = Intent {
            id: intent_id.clone(),
            creator: Addr::unchecked("user"),
            input_tokens: vec![BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(1000u128),
                is_native: true,
            }],
            intent_type: IntentType::Swap {
                output_tokens: vec![ExpectedToken {
                    token: "ujuno".to_string(),
                    is_native: true,
                    amount: Uint128::from(950u128),
                    target_address: None,
                }],
            },
            executor: None,
            status: IntentStatus::Pending,
            created_at: 1_000_000,
            origin_chain_id: "osmosis-1".to_string(),
            target_chain_id: "juno-1".to_string(),
            timeout: 1_000_100,
            tip: BeepCoin {
                token: "uatom".to_string(),
                amount: Uint128::from(10u128),
                is_native: true,
            },
            max_slippage: Some(50),
            partial_fill_allowed: false,
            filled_amount: Uint128::zero(),
            execution_fee: Uint128::from(5u128),
            retry_count: 0,
            priority: Priority::Normal,
        };

        // Save intent to storage
        INTENTS
            .save(&mut deps.storage, &intent_id, &intent)
            .unwrap();

        // Query the intent
        let result = query_intent(deps.as_ref(), intent_id.clone());

        // Assert success
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();

        // Validate fields
        assert_eq!(response.intent.id, intent.id);
        assert_eq!(response.intent.creator, intent.creator);
        assert_eq!(response.intent.origin_chain_id, intent.origin_chain_id);
        assert_eq!(response.intent.timeout, intent.timeout);
        assert_eq!(response.intent.created_at, intent.created_at);
        assert_eq!(response.intent.status, intent.status);
    }

    #[test]
    fn test_query_list_intents() {
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Create and store multiple intents
        let intents = vec![
            Intent {
                id: "intent-001".to_string(),
                creator: Addr::unchecked("user1"),
                input_tokens: vec![BeepCoin {
                    token: "uatom".to_string(),
                    amount: Uint128::from(1000u128),
                    is_native: true,
                }],
                intent_type: IntentType::Swap {
                    output_tokens: vec![ExpectedToken {
                        token: "ujuno".to_string(),
                        is_native: true,
                        amount: Uint128::from(950u128),
                        target_address: None,
                    }],
                },
                executor: None,
                status: IntentStatus::Pending,
                created_at: 1_000_000,
                origin_chain_id: "osmosis-1".to_string(),
                target_chain_id: "juno-1".to_string(),
                timeout: 1_000_100,
                tip: BeepCoin {
                    token: "uatom".to_string(),
                    amount: Uint128::from(10u128),
                    is_native: true,
                },
                max_slippage: Some(50),
                partial_fill_allowed: false,
                filled_amount: Uint128::zero(),
                execution_fee: Uint128::from(5u128),
                retry_count: 0,
                priority: Priority::Normal,
            },
            Intent {
                id: "intent-002".to_string(),
                creator: Addr::unchecked("user2"),
                input_tokens: vec![BeepCoin {
                    token: "uosmo".to_string(),
                    amount: Uint128::from(2000u128),
                    is_native: true,
                }],
                intent_type: IntentType::Swap {
                    output_tokens: vec![ExpectedToken {
                        token: "uatom".to_string(),
                        is_native: true,
                        amount: Uint128::from(1950u128),
                        target_address: None,
                    }],
                },
                executor: None,
                status: IntentStatus::Pending,
                created_at: 2_000_000,
                origin_chain_id: "juno-1".to_string(),
                target_chain_id: "osmosis-1".to_string(),
                timeout: 2_000_100,
                tip: BeepCoin {
                    token: "uosmo".to_string(),
                    amount: Uint128::from(20u128),
                    is_native: true,
                },
                max_slippage: Some(100),
                partial_fill_allowed: true,
                filled_amount: Uint128::zero(),
                execution_fee: Uint128::from(10u128),
                retry_count: 1,
                priority: Priority::High,
            },
        ];

        for intent in &intents {
            INTENTS.save(&mut deps.storage, &intent.id, intent).unwrap();
        }

        // Query starting from "intent-001" inclusively, limit 2
        let result = query_list_intents(deps.as_ref(), Some("intent-001".to_string()), Some(2));

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();

        // Should include "intent-001" and "intent-002"
        assert_eq!(response.intents.len(), 2);
        assert_eq!(response.intents[0].id, "intent-001");
        assert_eq!(response.intents[1].id, "intent-002");
    }

    #[test]
    fn test_query_get_user_nonce() {
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        let user_addr = Addr::unchecked("user1");

        // Case 1: No nonce stored — should return 0
        let result = query_get_user_nonce(deps.as_ref(), user_addr.clone());
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.nonce, 0u128);

        // Case 2: Store a nonce and query again
        USER_NONCE
            .save(&mut deps.storage, &user_addr, &42u128)
            .unwrap();

        let result = query_get_user_nonce(deps.as_ref(), user_addr.clone());
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.nonce, 42u128);
    }

    #[test]
    fn test_query_config_proposal() {
        let env = mock_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Define a sample config proposal
        let proposal_id = 1u64;
        let proposal = ConfigProposal {
            proposer: Addr::unchecked("admin"),
            config: UpdateConfig {
                supported_tokens: None,
                supported_protocols: None,
                default_timeout_height: None,
                max_intent_duration: None,
                min_intent_amount: None,
                emergency_pause: Some(true),
                rate_limit_per_user: None,
            },

            approvals: vec![Addr::unchecked("admin")],
            created_at: Timestamp::from_seconds(env.block.time.seconds()),
            expiry: Timestamp::from_seconds(env.block.time.seconds() + 120),
            threshold: Some(1),
            proposal_id,
        };

        // Save the proposal to storage
        CONFIG_PROPOSALS
            .save(&mut deps.storage, &proposal_id, &proposal)
            .unwrap();

        // Query the proposal
        let result = query_config_proposal(deps.as_ref(), proposal_id);

        // Assert success
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();

        // Validate fields
        assert_eq!(response.proposer, proposal.proposer);
        assert_eq!(
            response.config.supported_tokens,
            proposal.config.supported_tokens
        );
        assert_eq!(
            response.config.supported_protocols,
            proposal.config.supported_protocols
        );
        assert_eq!(
            response.config.default_timeout_height,
            proposal.config.default_timeout_height
        );
        assert_eq!(
            response.config.max_intent_duration,
            proposal.config.max_intent_duration
        );
        assert_eq!(
            response.config.min_intent_amount,
            proposal.config.min_intent_amount
        );
        assert_eq!(
            response.config.emergency_pause,
            proposal.config.emergency_pause
        );
        assert_eq!(
            response.config.rate_limit_per_user,
            proposal.config.rate_limit_per_user
        );
        assert_eq!(response.approvals, proposal.approvals);
        assert_eq!(response.created_at, proposal.created_at);
        assert_eq!(response.expiry, proposal.expiry);
        assert_eq!(response.threshold, proposal.threshold);
        assert_eq!(response.proposal_id, proposal_id);
    }

    #[test]
    fn test_query_health_status() {
        let mut deps = cosmwasm_std::testing::mock_dependencies();
        let env = cosmwasm_std::Env {
            block: cosmwasm_std::BlockInfo {
                height: 12345,
                time: cosmwasm_std::Timestamp::from_seconds(1_000_000),
                chain_id: "test-chain".to_string(),
            },
            transaction: None,
            contract: cosmwasm_std::ContractInfo {
                address: Addr::unchecked("contract"),
            },
        };

        // Case 1: No health status stored — should return default
        let result = query_health_status(deps.as_ref(), env.clone());
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();

        assert_eq!(response.is_healthy, true);
        assert_eq!(response.last_check, env.block.time);
        assert_eq!(response.last_check_height, env.block.height);
        assert_eq!(response.issues.len(), 0);
        assert_eq!(response.metrics.total_intents, 0);
        assert_eq!(response.metrics.total_value_locked, Uint128::zero());

        // Case 2: Store a custom health status
        let custom_health = HealthStatus {
            is_healthy: false,
            last_check: cosmwasm_std::Timestamp::from_seconds(999_999),
            last_check_height: 12000,
            issues: vec!["Node lag".to_string()],
            metrics: HealthMetrics {
                total_intents: 42,
                active_intents: 10,
                successful_executions: 30,
                failed_executions: 2,
                average_execution_time: 150,
                total_value_locked: Uint128::from(1_000_000u128),
            },
        };
        HEALTH_STATUS
            .save(&mut deps.storage, &custom_health)
            .unwrap();

        let result = query_health_status(deps.as_ref(), env.clone());
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();

        assert_eq!(response.is_healthy, false);
        assert_eq!(response.last_check, custom_health.last_check);
        assert_eq!(response.last_check_height, custom_health.last_check_height);
        assert_eq!(response.issues, custom_health.issues);
        assert_eq!(response.metrics.total_intents, 42);
        assert_eq!(
            response.metrics.total_value_locked,
            Uint128::from(1_000_000u128)
        );
    }

    #[test]
    fn test_query_wallet_balance() {
        let mut deps = cosmwasm_std::testing::mock_dependencies();
        let user_addr = Addr::unchecked("user1");

        // Case 1: No balance stored — should return empty balances
        let result = query_wallet_balance(deps.as_ref(), user_addr.clone());
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.address, user_addr);
        assert_eq!(response.balances.len(), 0);

        // Case 2: Store a wallet balance and query again
        let wallet_balance = WalletBalance {
            address: user_addr.clone(),
            balances: vec![
                BeepCoin {
                    token: "uatom".to_string(),
                    amount: Uint128::from(1000u128),
                    is_native: true,
                },
                BeepCoin {
                    token: "ujuno".to_string(),
                    amount: Uint128::from(500u128),
                    is_native: true,
                },
            ],
        };
        WALLET_BALANCES
            .save(&mut deps.storage, &user_addr, &wallet_balance)
            .unwrap();

        let result = query_wallet_balance(deps.as_ref(), user_addr.clone());
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.address, user_addr);
        assert_eq!(response.balances.len(), 2);
        assert_eq!(response.balances[0].token, "uatom");
        assert_eq!(response.balances[0].amount, Uint128::from(1000u128));
        assert_eq!(response.balances[1].token, "ujuno");
        assert_eq!(response.balances[1].amount, Uint128::from(500u128));
    }

    #[test]
    fn test_query_paymaster_reserve() {
        let mut deps = cosmwasm_std::testing::mock_dependencies();

        // Prepare a sample paymaster reserve
        let reserve = PaymasterReserve {
            balances: vec![
                BeepCoin {
                    token: "uatom".to_string(),
                    amount: Uint128::from(1000u128),
                    is_native: true,
                },
                BeepCoin {
                    token: "ujuno".to_string(),
                    amount: Uint128::from(500u128),
                    is_native: true,
                },
            ],
        };

        // Save it to storage
        PAYMASTER_RESERVE.save(&mut deps.storage, &reserve).unwrap();

        // Query the reserve
        let result = query_paymaster_reserve(deps.as_ref());
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();

        // Validate the balances
        assert_eq!(response.balances.len(), 2);
        assert_eq!(response.balances[0].token, "uatom");
        assert_eq!(response.balances[0].amount, Uint128::from(1000u128));
        assert_eq!(response.balances[1].token, "ujuno");
        assert_eq!(response.balances[1].amount, Uint128::from(500u128));
    }

    #[test]
    fn test_query_user_recovery() {
        let env = mock_env();
        let mut deps = cosmwasm_std::testing::mock_dependencies();
        let user = Addr::unchecked("user1");

        // Case 1: No recovery stored — should return default values
        let result = query_user_recovery(deps.as_ref(), user.clone());
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();

        assert_eq!(response.user, user);
        assert_eq!(response.new_address, None);
        assert_eq!(response.initiated_at, None);
        assert_eq!(response.guardian_approvals.len(), 0);
        assert_eq!(response.threshold, 0);
        assert_eq!(response.delay, 48 * 3600);

        // Case 2: Store a recovery and query again
        let recovery = UserRecovery {
            user: user.clone(),
            new_address: Some(Addr::unchecked("new_user")),
            initiated_at: Some(Timestamp::from_seconds(env.block.time.seconds())),
            guardian_approvals: vec![Addr::unchecked("guardian1"), Addr::unchecked("guardian2")],
            threshold: 2,
            delay: 72 * 3600,
        };
        USER_RECOVERIES
            .save(&mut deps.storage, &user, &recovery)
            .unwrap();

        let result = query_user_recovery(deps.as_ref(), user.clone());
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let response = result.unwrap();

        assert_eq!(response.user, user);
        assert_eq!(response.new_address, Some(Addr::unchecked("new_user")));
        assert_eq!(
            response.initiated_at,
            Some(Timestamp::from_seconds(env.block.time.seconds()))
        );
        assert_eq!(response.guardian_approvals.len(), 2);
        assert_eq!(response.guardian_approvals[0], Addr::unchecked("guardian1"));
        assert_eq!(response.guardian_approvals[1], Addr::unchecked("guardian2"));
        assert_eq!(response.threshold, 2);
        assert_eq!(response.delay, 72 * 3600);
    }
}
