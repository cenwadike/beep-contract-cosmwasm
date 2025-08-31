# Beep Contract CosmWasm

## Overview

This a CosmWasm smart contract designed for cross-chain intent-based transactions, enabling users
to create, fill, and cancel intents for token swaps and other operations across different 
blockchain networks. It supports Inter-Blockchain Communication (IBC) for cross-chain interactions,
multi-signature governance, and robust security features like circuit breakers and rate limiting. 
The contract facilitates secure token transfers, wallet management, and recovery mechanisms while 
maintaining a flexible configuration for supported tokens and protocols.

## Key Features

- **Intent Management**: Users can create, fill, or cancel intents for token swaps or other 
predefined actions, with support for both same-chain and cross-chain operations via IBC.

- **Multi-Signature Governance**: Contract configuration updates and recovery processes require 
approval from multiple owners or guardians, based on a configurable threshold.

- **Security Mechanisms**:
    - **Circuit Breaker**: Allows pausing contract operations in emergencies, with a reset 
        mechanism requiring guardian approvals.
    - **Rate Limiting**: Restricts the number of transactions per user within a time period to 
        prevent abuse.
    - **Blacklist**: Prevents blacklisted addresses from interacting with the contract.
    - **Emergency Pause**: Admins or guardians can pause the contract in critical situations.

- **Wallet Management**: Users can deposit and transfer tokens to/from their wallet balances within 
    the contract.
- **Paymaster System**: Funds gas fees through user wallet balances, transaction funds, or a 
    paymaster reserve.
- **IBC Support**: Facilitates cross-chain intent execution with validated IBC channels and 
    unordered packet ordering.
- **Recovery Mechanisms**: Supports owner and user recovery processes with guardian approvals and 
    time delays.

## Contract Structure

### Entry Points

- **Instantiate**: Initializes the contract with owners, guardians, supported tokens, protocols, 
    and other configuration parameters.
- **Execute**: Handles various operations like intent creation, filling, cancellation, 
    configuration updates, and recovery processes.
- **Query**: Provides read-only access to contract state, including configuration, intents, wallet 
    balances, and health status.
- **IBC Functions**: Manages IBC channel operations and packet handling for cross-chain intent 
    execution.

### Key Modules

- **States**: Stores critical data like configuration, intents, wallet balances, and recovery 
    proposals.
- **Validations**: Ensures input validation for intents, tokens, and configurations.
- **Security**: Implements rate limiting, blacklisting, and circuit breaker checks.
- **Utils**: Manages nonce increments and other utilities.
- **Types**: Defines data structures like Intent, Config, BeepCoin, and FeeStructure.

## Setup and Testing

### Prerequisites

- Rust and CosmWasm development environment.
- A compatible blockchain network supporting CosmWasm smart contracts.
- IBC-enabled blockchain for cross-chain functionality.

### Setup Steps

- **Compile the Contract**:
    - Use ```cargo build --release --target wasm32-unknown-unknown``` to generate the WASM binary.


- **Run tests**:

    - Use ```cargo test``` to test contract



- Configure IBC Connections:
Use ```AddIbcConnection``` to register IBC channels for cross-chain operations.

## Example Instantiation

```
{
  "owners": ["cosmos1...", "cosmos2..."],
  "guardians": ["cosmos3...", "cosmos4..."],
  "threshold": 2,
  "supported_tokens": ["udenom", "cw20:cosmos5..."],
  "supported_protocols": ["protocol1", "protocol2"],
  "default_timeout_height": 1000
}
```

## Usage

### Creating an Intent

- **Message**: `ExecuteMsg::CreateIntent`
- **Parameters**:
    - `intent_id`: Unique identifier for the intent.
    - `input_tokens`: List of tokens to be used.
    - `intent_type`: Type of intent (e.g., Swap, LiquidStake).
    - `target_chain_id`: Destination chain for cross-chain intents.
    - `timeout`: Optional expiration height.
    - `tip`: Token amount for executor incentive.
    - `max_slippage`: Maximum allowed slippage for swaps.
    - `partial_fill_allowed`: Whether partial filling is permitted.
    - `priority`: Transaction priority (Low, Normal, High, Urgent).
    - `use_wallet_balance`: Whether to use wallet balance for funding.


### Example:
```
{
  "create_intent": {
    "intent_id": "intent_001",
    "input_tokens": [{"token": "udenom", "amount": "1000", "is_native": true}],
    "intent_type": {"swap": {"output_tokens": [{"token": "utoken", "amount": "950"}]}},
    "target_chain_id": "chain-2",
    "tip": {"token": "udenom", "amount": "10", "is_native": true},
    "priority": "normal"
  }
}
```

### Filling an Intent

- **Message**: `ExecuteMsg::FillIntent`
- **Parameters**:
    - `intent_id`: ID of the intent to fill.
    - `source_chain_id`: Chain where the intent is being filled.
    - `intent_type`: Must match the intent’s type.
    - `use_wallet_balance`: Whether to use wallet balance for gas.
- **Behavior**: Transfers input tokens and tip to the executor and output tokens to the recipient.

### Canceling an Intent

- **Message**: `ExecuteMsg::CancelIntent`
- **Parameters**: `intent_id`
- **Behavior**: Returns escrowed tokens to the creator if the intent is cancellable.

### Wallet Operations

- **Deposit**: `ExecuteMsg::DepositToWallet` to add tokens to the user’s wallet balance.
- **Transfer**: `ExecuteMsg::TransferFromWallet` to send tokens from the wallet to a recipient.

### Governance

- **Propose Config Update**: `ExecuteMsg::ProposeConfigUpdate` to suggest changes to tokens, protocols, or timeout.
**Approve/Execute Proposal**: Use `ApproveConfigProposal` and `ExecuteConfigProposal` for multi-signature approval.
- **Recovery**: `InitiateRecovery` and `ApproveRecovery` for admin recovery; `InitiateUserRecovery` and `ApproveUserRecovery` for user wallet recovery.

### Security Operations

- **Trigger Circuit Breaker**: `ExecuteMsg::TriggerCircuitBreaker` to pause non-admin/guardian operations.
- **Reset Circuit Breaker**: `ExecuteMsg::ResetCircuitBreaker` to resume operations after guardian approvals.

## Security Considerations

- **Validation**: All inputs are rigorously validated to prevent invalid configurations or duplicate entries.
- **Access Control**: Only authorized owners or guardians can perform sensitive operations.
- **Rate Limiting**: Prevents spamming by limiting user transactions per day.
- **Circuit Breaker**: Protects the contract during vulnerabilities or attacks.
- **Recovery Delay**: 48-hour delay for recovery actions to prevent hasty changes.

## Querying the Contract

### Available Queries:

- `GetConfig`: Returns contract configuration.
- `GetConnection`: Returns IBC connection details for a chain.
- `GetIntent`: Retrieves a specific intent.
- `ListIntents`: Lists intents with pagination.
- `GetUserNonce`: Returns a user’s nonce.
- `GetConfigProposal`: Retrieves a configuration proposal.
- `GetHealthStatus`: Returns contract health metrics.
- `GetWalletBalance`: Returns a user’s wallet balance.
- `GetPaymasterReserve`: Returns paymaster reserve balances.
- `GetUserRecovery`: Returns user recovery details.

## Onboarding Guide

### Understand the Contract:
- Review the contract’s purpose: intent-based cross-chain transactions.
Familiarize yourself with key concepts: intents, IBC, multi-signature governance, and paymaster.

### Set Up Development Environment:
- Install Rust and a CosmWasm-compatible blockchain node.
Clone the contract repository and build the WASM binary.

### Test Locally:
- Test intent creation, filling, and cancellation using sample messages.
Verify IBC functionality with a mock IBC channel.

### Interact with the Contract:
- Use a CosmWasm client to send execute and query messages.
Monitor contract health using GetHealthStatus.

## Contribute or Extend:
- Add support for new intent types (e.g., `LiquidStake`, `Lend`) by extending IntentType.
- Enhance security or add new governance features as needed.

## Limitations

- Some intent types (e.g., `LiquidStake`, `Lend`) are unimplemented.
- Gas payment requires sufficient funds in wallet, transaction, or paymaster reserve.
- Recovery processes require guardian coordination and a 48-hour delay.

## Future Enhancements

- Implement additional intent types.
- Add support for dynamic fee adjustments.
- Enhance metrics tracking for better health monitoring.
- Introduce more granular access control for specific operations.

# Support
_For issues or contributions, contact the development team via the repository’s issue tracker or community channels._