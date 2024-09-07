use core::num::traits::Zero;
use core::array::ArrayTrait;
use payment_mandate::mandate_account::MandateAccountComponent::{
    InternalTrait, SRC6CamelOnlyImpl, SRC6Impl
};
use payment_mandate::mandate_account::MandateAccountComponent::{PublicKeyCamelImpl, PublicKeyImpl};
use openzeppelin::account::interface::{ISRC6, ISRC6_ID};
use payment_mandate::interfaces::imandate::{
    IPaymentMandate, MandateAccountABIDispatcher, MandateAccountABIDispatcherTrait
};
use payment_mandate::mandate_account::MandateAccountComponent;
use payment_mandate::types::common::Mandate;
use super::mock_account::MandateAccountMock;
use openzeppelin::tests::utils;
use openzeppelin::token::erc20::interface::{IERC20DispatcherTrait, IERC20Dispatcher};
use openzeppelin::utils::selectors;
use openzeppelin::utils::serde::SerializedAppend;
use super::erc20::ERC20Upgradeable;
use starknet::ContractAddress;
use starknet::account::Call;
use starknet::contract_address_const;
use starknet::testing;
use starknet::get_contract_address;
use starknet::syscalls::{deploy_syscall, call_contract_syscall};
use super::constants::{
    PUBKEY, NEW_PUBKEY, SALT, ZERO, QUERY_OFFSET, QUERY_VERSION, MIN_TRANSACTION_VERSION
};

#[derive(Drop)]
pub(crate) struct SignedTransactionData {
    pub(crate) private_key: felt252,
    pub(crate) public_key: felt252,
    pub(crate) transaction_hash: felt252,
    pub(crate) r: felt252,
    pub(crate) s: felt252
}

pub(crate) fn SIGNED_TX_DATA() -> SignedTransactionData {
    SignedTransactionData {
        private_key: 1234,
        public_key: NEW_PUBKEY,
        transaction_hash: 0x601d3d2e265c10ff645e1554c435e72ce6721f0ba5fc96f0c650bfc6231191a,
        r: 0x6bc22689efcaeacb9459577138aff9f0af5b77ee7894cdc8efabaf760f6cf6e,
        s: 0x295989881583b9325436851934334faa9d639a2094cd1e2f8691c8a71cd4cdf
    }
}

type ComponentState = MandateAccountComponent::ComponentState<MandateAccountMock::ContractState>;

fn COMPONENT_STATE() -> ComponentState {
    MandateAccountComponent::component_state_for_testing()
}

fn CLASS_HASH() -> felt252 {
    MandateAccountMock::TEST_CLASS_HASH
}


fn setup() -> ComponentState {
    let mut state = COMPONENT_STATE();
    state.initializer(PUBKEY);
    state
}

fn deploy(
    contract_class_hash: felt252, salt: felt252, calldata: Array<felt252>
) -> ContractAddress {
    let (address, _) = deploy_syscall(
        contract_class_hash.try_into().unwrap(), salt, calldata.span(), false
    )
        .unwrap();
    address
}

fn setup_dispatcher(
    data: Option<@SignedTransactionData>
) -> (MandateAccountABIDispatcher, ContractAddress) {
    testing::set_version(MIN_TRANSACTION_VERSION);

    let mut calldata = array![];
    if data.is_some() {
        let data = data.unwrap();
        testing::set_signature(array![*data.r, *data.s].span());
        testing::set_transaction_hash(*data.transaction_hash);
        calldata.append(PUBKEY);
    //calldata.append(*data.public_key);
    } else {
        calldata.append(PUBKEY);
    }
    let address = utils::deploy(CLASS_HASH(), calldata);
    (MandateAccountABIDispatcher { contract_address: address }, address)
}

fn deploy_erc20(recipient: ContractAddress) -> (IERC20Dispatcher, ContractAddress) {
    let owner: ContractAddress = contract_address_const::<100>();
    let name: ByteArray = "ERC20";
    let symbol: ByteArray = "TKT";
    let fixed_supply: u256 = 100;

    let mut calldata = ArrayTrait::<felt252>::new();
    name.serialize(ref calldata);
    symbol.serialize(ref calldata);
    fixed_supply.serialize(ref calldata);
    recipient.serialize(ref calldata);
    owner.serialize(ref calldata);
    let erc20_token_address = deploy(ERC20Upgradeable::TEST_CLASS_HASH, 1, calldata);
    return (IERC20Dispatcher { contract_address: erc20_token_address }, erc20_token_address);
}


#[test]
fn test_is_valid_mandate_signature() {
    let mut state = COMPONENT_STATE();
    let data = SIGNED_TX_DATA();
    let (account, account_address) = setup_dispatcher(Option::Some(@data));
    let hash = data.transaction_hash;

    testing::set_contract_address(account_address);
    let mandate_id = account
        .add_mandate(
            Mandate {
                executor_public_key: data.public_key,
                pay_to: contract_address_const::<0x4567>(),
                currency_address: contract_address_const::<0x1234>(),
                amount: 100,
                day_of_month: 1,
                valid_till_timestamp: 1234567,
                num_executed: 0,
                last_executed_timestamp: 0,
                is_active: false
            }
        );

    let mut calldata = array![];

    mandate_id.serialize(ref calldata);
    let call = Call {
        to: account_address, selector: selector!("execute_mandate"), calldata: calldata.span()
    };
    let mut calls = array![];
    calls.append(call);

    let is_valid = account.__validate__(calls);
    assert_eq!(is_valid, starknet::VALIDATED);
}

#[test]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_invalid_mandate_signature() {
    let mut state = COMPONENT_STATE();
    let data = SIGNED_TX_DATA();
    let (account, account_address) = setup_dispatcher(Option::Some(@data));
    let hash = data.transaction_hash;

    testing::set_contract_address(account_address);
    let mandate_id = account
        .add_mandate(
            Mandate {
                executor_public_key: data.public_key + 100,
                pay_to: contract_address_const::<0x4567>(),
                currency_address: contract_address_const::<0x1234>(),
                amount: 100,
                day_of_month: 1,
                valid_till_timestamp: 1234567,
                num_executed: 0,
                last_executed_timestamp: 0,
                is_active: false
            }
        );

    let mut calldata = array![];

    mandate_id.serialize(ref calldata);
    let call = Call {
        to: account_address, selector: selector!("execute_mandate"), calldata: calldata.span()
    };
    let mut calls = array![];
    calls.append(call);

    let is_valid = account.__validate__(calls);
    assert_eq!(is_valid, starknet::VALIDATED);
}

#[test]
#[should_panic(expected: ('Account: invalid mandate id', 'ENTRYPOINT_FAILED'))]
fn test_invalid_mandate_id() {
    let mut state = COMPONENT_STATE();
    let data = SIGNED_TX_DATA();
    let (account, account_address) = setup_dispatcher(Option::Some(@data));
    let hash = data.transaction_hash;

    testing::set_contract_address(account_address);
    let mandate_id = account
        .add_mandate(
            Mandate {
                executor_public_key: data.public_key,
                pay_to: contract_address_const::<0x4567>(),
                currency_address: contract_address_const::<0x1234>(),
                amount: 100,
                day_of_month: 1,
                valid_till_timestamp: 1234567,
                num_executed: 0,
                last_executed_timestamp: 0,
                is_active: false
            }
        );

    let new_mandate_id = mandate_id + 1;
    let mut calldata = array![];

    new_mandate_id.serialize(ref calldata);
    let call = Call {
        to: account_address, selector: selector!("execute_mandate"), calldata: calldata.span()
    };
    let mut calls = array![];
    calls.append(call);

    let is_valid = account.__validate__(calls);
    assert_eq!(is_valid, starknet::VALIDATED);
}

#[test]
#[should_panic(expected: ('Account: invalid mandate', 'ENTRYPOINT_FAILED'))]
fn test_invalid_mandate_to() {
    let mut state = COMPONENT_STATE();
    let data = SIGNED_TX_DATA();
    let (account, account_address) = setup_dispatcher(Option::Some(@data));
    let hash = data.transaction_hash;

    testing::set_contract_address(account_address);
    let mandate_id = account
        .add_mandate(
            Mandate {
                executor_public_key: data.public_key,
                pay_to: contract_address_const::<0x4567>(),
                currency_address: contract_address_const::<0x1234>(),
                amount: 100,
                day_of_month: 1,
                valid_till_timestamp: 1234567,
                num_executed: 0,
                last_executed_timestamp: 0,
                is_active: false
            }
        );

    let mut calldata = array![];

    mandate_id.serialize(ref calldata);
    let call = Call {
        to: contract_address_const::<0x4567>(),
        selector: selector!("execute_mandate"),
        calldata: calldata.span()
    };
    let mut calls = array![];
    calls.append(call);

    let is_valid = account.__validate__(calls);
    assert_eq!(is_valid, starknet::VALIDATED);
}

#[test]
fn test_valid_mandate_execution() {
    let mut state = COMPONENT_STATE();
    let data = SIGNED_TX_DATA();
    let (account, account_address) = setup_dispatcher(Option::Some(@data));
    let (erc20, erc20_address) = deploy_erc20(account_address);
    let hash = data.transaction_hash;

    let mut good_signature = array![data.r, data.s];
    let mut bad_signature = array![0x987, 0x564];

    testing::set_contract_address(account_address);
    let recipient = contract_address_const::<0x4567>();
    let sent_amount: u256 = 40;
    let mandate_id = account
        .add_mandate(
            Mandate {
                executor_public_key: data.public_key,
                pay_to: recipient,
                currency_address: erc20_address,
                amount: sent_amount,
                day_of_month: 1,
                valid_till_timestamp: 1825643152,
                num_executed: 0,
                last_executed_timestamp: 0,
                is_active: false
            }
        );

    println!("Mandate id:{}", mandate_id);
    println!("Sender balance before:{}", erc20.balance_of(account_address));
    println!("Recipient balance before:{}", erc20.balance_of(recipient));

    let mut calldata = array![];

    mandate_id.serialize(ref calldata);
    let call = Call {
        to: account_address, selector: selector!("execute_mandate"), calldata: calldata.span()
    };
    let mut calls = array![];
    calls.append(call);
    testing::set_block_timestamp(1727803152);

    testing::set_contract_address(contract_address_const::<0x0>());
    let ret_values = account.__execute__(calls);

    println!("Sender balance after:{}", erc20.balance_of(account_address));
    println!("Recipient balance after:{}", erc20.balance_of(recipient));

    assert_eq!(erc20.balance_of(recipient), sent_amount);
    assert_eq!(erc20.balance_of(account_address), 100 - sent_amount);
//assert_eq!(is_valid, starknet::VALIDATED);
}
