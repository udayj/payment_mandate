use starknet::ContractAddress;
use payment_mandate::types::common::Mandate;

#[starknet::interface]
pub trait IPaymentMandate<TState> {

    fn add_mandate(ref self: TState, mandate: Mandate) -> u128;
    fn remove_mandate(ref self: TState, mandate_id: u128);
    fn execute_mandate(ref self: TState, mandate_id: u128) -> bool;
}

// setup mandate
// assert only self
// validate mandate, save in storage

// remove mandate

// execute_mandate
// transfer tokens


