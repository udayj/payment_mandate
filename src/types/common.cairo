use starknet::ContractAddress;

#[derive(Drop,starknet::Store, Serde, Copy)]
pub struct Mandate {
    pub executor_public_key: felt252,
    pub pay_to: ContractAddress,
    pub currency_address: ContractAddress,
    pub amount: u256,
    pub day_of_month: u64,
    pub valid_till_timestamp: u64,
    pub num_executed: u128,
    pub last_executed_timestamp: u64,
    pub is_active: bool
}

#[derive(Drop)]
pub struct Date {
    pub year: u64,
    pub month: u64,
    pub day: u64
}
