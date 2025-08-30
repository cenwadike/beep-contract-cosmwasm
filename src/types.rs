use cosmwasm_std::{Addr, Binary, Timestamp, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
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
pub struct UpdateConfig {
    pub supported_tokens: Option<Vec<String>>,
    pub supported_protocols: Option<Vec<String>>,
    pub default_timeout_height: Option<u64>,
    pub max_intent_duration: Option<u64>,
    pub min_intent_amount: Option<Uint128>,
    pub emergency_pause: Option<bool>,
    pub rate_limit_per_user: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct BeepCoin {
    pub token: String,
    pub amount: Uint128,
    pub is_native: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ExpectedToken {
    pub token: String,
    pub is_native: bool,
    pub amount: Uint128,
    pub target_address: Option<Addr>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Intent {
    pub id: String,
    pub creator: Addr,
    pub input_tokens: Vec<BeepCoin>,
    pub intent_type: IntentType,
    pub executor: Option<Addr>,
    pub status: IntentStatus,
    pub created_at: u64,
    pub origin_chain_id: String,
    pub target_chain_id: String,
    pub timeout: u64,
    pub tip: BeepCoin,
    pub max_slippage: Option<u64>,
    pub partial_fill_allowed: bool,
    pub filled_amount: Uint128,
    pub execution_fee: Uint128,
    pub retry_count: u32,
    pub priority: Priority,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum IntentType {
    Swap {
        output_tokens: Vec<ExpectedToken>,
    },
    LiquidStake {
        validator: String,
        output_denom: String,
    },
    Lend {
        protocol: String,
        interest_rate_mode: u8,
    },
    Generic {
        action_type: String,
        params: Binary,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum IntentStatus {
    Active,
    Pending,
    Completed,
    Failed { reason: String },
    Expired,
    Cancelled,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum Priority {
    Low,
    Normal,
    High,
    Urgent,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Connection {
    pub chain_id: String,
    pub port: String,
    pub channel_id: String,
    pub is_active: bool,
    pub last_updated: Timestamp,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Recovery {
    pub proposed_owner: Option<Addr>,
    pub initiated_at: Option<Timestamp>,
    pub guardian_approvals: Vec<Addr>,
    pub threshold: u32,
    pub delay: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct UserRecovery {
    pub user: Addr,
    pub new_address: Option<Addr>,
    pub initiated_at: Option<Timestamp>,
    pub guardian_approvals: Vec<Addr>,
    pub threshold: u32,
    pub delay: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ConfigProposal {
    pub proposer: Addr,
    pub config: UpdateConfig,
    pub approvals: Vec<Addr>,
    pub created_at: Timestamp,
    pub expiry: Timestamp,
    pub threshold: Option<u32>,
    pub proposal_id: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct RateLimit {
    pub user: Addr,
    pub day: u64,
    pub count: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct CircuitBreakerState {
    pub is_triggered: bool,
    pub trigger_reason: Option<String>,
    pub triggered_at: Option<Timestamp>,
    pub triggered_by: Option<Addr>,
    pub reset_approvals: Vec<Addr>,
    pub reset_threshold: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct FeeStructure {
    pub base_fee: Uint128,
    pub percentage_fee: u32,
    pub gas_price: Uint128,
    pub priority_multiplier: Vec<(Priority, u32)>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct BlacklistEntry {
    pub address: Addr,
    pub reason: String,
    pub added_at: Timestamp,
    pub added_by: Addr,
    pub severity: SecuritySeverity,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub timestamp: Timestamp,
    pub actor: Addr,
    pub details: String,
    pub severity: SecuritySeverity,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum SecurityEventType {
    RateLimitExceeded,
    BlacklistAdded,
    BlacklistRemoved,
    CircuitBreakerTriggered,
    CircuitBreakerReset,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub last_check: Timestamp,
    pub last_check_height: u64,
    pub issues: Vec<String>,
    pub metrics: HealthMetrics,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct HealthMetrics {
    pub total_intents: u64,
    pub active_intents: u64,
    pub successful_executions: u64,
    pub failed_executions: u64,
    pub average_execution_time: u64,
    pub total_value_locked: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct WalletBalance {
    pub address: Addr,
    pub balances: Vec<BeepCoin>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PaymasterReserve {
    pub balances: Vec<BeepCoin>,
}

impl Intent {
    pub fn can_be_filled(&self) -> bool {
        matches!(self.status, IntentStatus::Active)
    }

    pub fn can_be_cancelled(&self) -> bool {
        matches!(self.status, IntentStatus::Active)
    }
}
