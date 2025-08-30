use crate::types::{BeepCoin, HealthMetrics, Intent, IntentType, Priority, UpdateConfig};
use cosmwasm_std::{Addr, Timestamp, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub supported_tokens: Vec<String>,
    pub supported_protocols: Vec<String>,
    pub default_timeout_height: u64,
    pub owners: Vec<String>,
    pub threshold: u32,
    pub guardians: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IbcExecuteMsg {
    FillIntent { intent_id: String, executor: Addr },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    CreateIntent {
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
    },
    FillIntent {
        intent_id: String,
        source_chain_id: String,
        intent_type: IntentType,
        use_wallet_balance: bool,
    },
    CancelIntent {
        intent_id: String,
    },
    UpdateAdmin {
        new_admin: Addr,
    },
    AddSupportedTokens {
        tokens: Vec<String>,
    },
    RemoveSupportedTokens {
        tokens: Vec<String>,
    },
    AddSupportedProtocols {
        protocols: Vec<String>,
    },
    RemoveSupportedProtocols {
        protocols: Vec<String>,
    },
    UpdateDefaultTimeoutHeight {
        default_timeout_height: u64,
    },
    AddIbcConnection {
        chain_id: String,
        port: String,
        channel_id: String,
    },
    UpdateIbcConnection {
        chain_id: String,
        port: Option<String>,
        channel_id: Option<String>,
        is_active: Option<bool>,
    },
    RemoveIbcConnection {
        chain_id: String,
    },
    ProposeConfigUpdate {
        proposal_id: u64,
        threshold: Option<u32>,
        supported_tokens: Option<Vec<String>>,
        supported_protocols: Option<Vec<String>>,
        default_timeout_height: Option<u64>,
    },
    ApproveConfigProposal {
        proposal_id: u64,
    },
    ExecuteConfigProposal {
        proposal_id: u64,
    },
    InitiateRecovery {
        proposed_owner: Addr,
    },
    ApproveRecovery {},
    InitiateUserRecovery {
        user: Addr,
        new_address: Addr,
    },
    ApproveUserRecovery {
        user: Addr,
    },
    TriggerCircuitBreaker {
        reason: String,
    },
    ResetCircuitBreaker {},
    DepositToWallet {
        tokens: Vec<BeepCoin>,
    },
    TransferFromWallet {
        recipient: Addr,
        tokens: Vec<BeepCoin>,
    },
    PaymasterFund {
        tokens: Vec<BeepCoin>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetConfig {},
    GetConnection {
        chain_id: String,
    },
    GetIntent {
        id: String,
    },
    ListIntents {
        start_after: Option<String>,
        limit: Option<u32>,
    },
    GetUserNonce {
        address: Addr,
    },
    GetConfigProposal {
        proposal_id: u64,
    },
    GetHealthStatus {},
    GetWalletBalance {
        address: Addr,
    },
    GetPaymasterReserve {},
    GetUserRecovery {
        user: Addr,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ConfigResponse {
    pub admin: Addr,
    pub supported_tokens: Vec<String>,
    pub supported_protocols: Vec<String>,
    pub default_timeout_height: u64,
    pub fee_collector: Addr,
    pub max_intent_duration: u64,
    pub min_intent_amount: Uint128,
    pub emergency_pause: bool,
    pub rate_limit_per_user: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ConnectionResponse {
    pub chain_id: String,
    pub port: String,
    pub channel_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct IntentResponse {
    pub intent: Intent,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct IntentsResponse {
    pub intents: Vec<Intent>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct UserNonceResponse {
    pub nonce: u128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ConfigProposalResponse {
    pub proposer: Addr,
    pub config: UpdateConfig,
    pub approvals: Vec<Addr>,
    pub created_at: Timestamp,
    pub expiry: Timestamp,
    pub threshold: Option<u32>,
    pub proposal_id: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct HealthStatusResponse {
    pub is_healthy: bool,
    pub last_check: Timestamp,
    pub last_check_height: u64,
    pub issues: Vec<String>,
    pub metrics: HealthMetrics,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct WalletBalanceResponse {
    pub address: Addr,
    pub balances: Vec<BeepCoin>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PaymasterReserveResponse {
    pub balances: Vec<BeepCoin>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct UserRecoveryResponse {
    pub user: Addr,
    pub new_address: Option<Addr>,
    pub initiated_at: Option<Timestamp>,
    pub guardian_approvals: Vec<Addr>,
    pub threshold: u32,
    pub delay: u64,
}
