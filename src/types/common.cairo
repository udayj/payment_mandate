use starknet::ContractAddress;

#[derive(Drop,starknet::Store, Serde)]
pub struct Mandate {
    pub executor_public_key: felt252,
    pub pay_to: ContractAddress,
    pub currency_address: ContractAddress,
    pub amount: u256,
    pub day_of_month: u8,
    pub valid_till_timestamp: u64,
    pub num_executed: u128,
    pub last_executed_timestamp: u64,
    pub status: bool
}
