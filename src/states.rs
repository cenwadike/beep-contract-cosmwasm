use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

use crate::types::{
    BeepCoin, BlacklistEntry, CircuitBreakerState, Config, ConfigProposal, Connection,
    FeeStructure, HealthStatus, Intent, PaymasterReserve, RateLimit, Recovery, SecurityEvent,
    UserRecovery, WalletBalance,
};

// Contract configuration
pub const CONFIG: Item<Config> = Item::new("config");

// Owner management
pub const OWNERS: Item<Vec<Addr>> = Item::new("owners");
pub const THRESHOLD: Item<u32> = Item::new("threshold");
pub const NONCE: Item<u64> = Item::new("nonce");

// Guardian management
pub const GUARDIANS: Item<Vec<Addr>> = Item::new("guardians");

// Recovery settings
pub const RECOVERY: Item<Recovery> = Item::new("recovery");

// Intent storage
pub const INTENTS: Map<&str, Intent> = Map::new("intents");
pub const ESCROW: Map<(&Addr, &str), Vec<BeepCoin>> = Map::new("escrow");

// Configuration proposals
pub const CONFIG_PROPOSALS: Map<&u64, ConfigProposal> = Map::new("config_proposals");

// Circuit breaker
pub const CIRCUIT_BREAKER: Item<CircuitBreakerState> = Item::new("circuit_breaker");

// Fee structure
pub const FEE_STRUCTURE: Item<FeeStructure> = Item::new("fee_structure");

// Rate limiting
pub const RATE_LIMITS: Map<(&Addr, u64), RateLimit> = Map::new("rate_limits");

// Blacklist
pub const BLACKLISTED_ADDRESSES: Map<&Addr, BlacklistEntry> = Map::new("blacklisted_addresses");

// IBC connections
pub const IBC_CONNECTIONS: Map<&str, Connection> = Map::new("ibc_connections");

// Security events
pub const SECURITY_EVENTS: Map<(u64, &str), SecurityEvent> = Map::new("security_events");

// Health status
pub const HEALTH_STATUS: Item<HealthStatus> = Item::new("health_status");

// User nonces
pub const USER_NONCE: Map<&Addr, u128> = Map::new("user_nonce");

// User wallet balance
pub const WALLET_BALANCES: Map<&Addr, WalletBalance> = Map::new("wallet_balances");

// Paymaster tokens balance
pub const PAYMASTER_RESERVE: Item<PaymasterReserve> = Item::new("paymaster_reserve");

// User wallet recoveries
pub const USER_RECOVERIES: Map<&Addr, UserRecovery> = Map::new("user_recoveries");
