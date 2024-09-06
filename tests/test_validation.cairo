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
use starknet::ContractAddress;
use starknet::account::Call;
use starknet::contract_address_const;
use starknet::testing;
use starknet::get_contract_address;
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

#[test]
fn test_is_valid_signature() {
    let mut state = COMPONENT_STATE();
    let data = SIGNED_TX_DATA();
    let hash = data.transaction_hash;

    let mut good_signature = array![data.r, data.s];
    let mut bad_signature = array![0x987, 0x564];

    state._set_public_key(data.public_key);

    let is_valid = state.is_valid_signature(hash, good_signature);
    assert_eq!(is_valid, starknet::VALIDATED);

    let is_valid = state.is_valid_signature(hash, bad_signature);
    assert!(is_valid.is_zero(), "Should reject invalid signature");
}

#[test]
fn test_is_valid_mandate_signature() {
    let mut state = COMPONENT_STATE();
    let data = SIGNED_TX_DATA();
    let (account, account_address) = setup_dispatcher(Option::Some(@data));
    let hash = data.transaction_hash;

    let mut good_signature = array![data.r, data.s];
    let mut bad_signature = array![0x987, 0x564];

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

    println!("Mandate id:{}", mandate_id);
    let mut calldata = array![];

    mandate_id.serialize(ref calldata);
    let call = Call {
        to: account_address, selector: selector!("execute_mandate"), calldata: calldata.span()
    };
    let mut calls = array![];
    calls.append(call);

    let is_valid = account.__validate__(calls);
    assert_eq!(is_valid, starknet::VALIDATED);
//let is_valid = state.is_valid_signature(hash, bad_signature);
//assert!(is_valid.is_zero(), "Should reject invalid signature");
}
// check whether mandate is validated correctly
// check whether mandate is invalidated correctly
// check whether mandate can be executed - deploy some ERC20, give balance to account holder
// check whether mandate execution is halted correctly
#[test]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_invalid_mandate_signature() {
    let mut state = COMPONENT_STATE();
    let data = SIGNED_TX_DATA();
    let (account, account_address) = setup_dispatcher(Option::Some(@data));
    let hash = data.transaction_hash;

    let mut good_signature = array![data.r, data.s];
    let mut bad_signature = array![0x987, 0x564];

    testing::set_contract_address(account_address);
    let mandate_id = account
        .add_mandate(
            Mandate {
                executor_public_key: data.public_key+100,
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

    println!("Mandate id:{}", mandate_id);
    let mut calldata = array![];

    mandate_id.serialize(ref calldata);
    let call = Call {
        to: account_address, selector: selector!("execute_mandate"), calldata: calldata.span()
    };
    let mut calls = array![];
    calls.append(call);

    let is_valid = account.__validate__(calls);
    assert_eq!(is_valid, starknet::VALIDATED);
//let is_valid = state.is_valid_signature(hash, bad_signature);
//assert!(is_valid.is_zero(), "Should reject invalid signature");
}

#[test]
#[should_panic(expected: ('Account: invalid mandate id', 'ENTRYPOINT_FAILED'))]
fn test_invalid_mandate_id() {
    let mut state = COMPONENT_STATE();
    let data = SIGNED_TX_DATA();
    let (account, account_address) = setup_dispatcher(Option::Some(@data));
    let hash = data.transaction_hash;

    let mut good_signature = array![data.r, data.s];
    let mut bad_signature = array![0x987, 0x564];

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
//let is_valid = state.is_valid_signature(hash, bad_signature);
//assert!(is_valid.is_zero(), "Should reject invalid signature");
}

#[test]
#[should_panic(expected: ('Account: invalid mandate', 'ENTRYPOINT_FAILED'))]
fn test_invalid_mandate_to() {
    let mut state = COMPONENT_STATE();
    let data = SIGNED_TX_DATA();
    let (account, account_address) = setup_dispatcher(Option::Some(@data));
    let hash = data.transaction_hash;

    let mut good_signature = array![data.r, data.s];
    let mut bad_signature = array![0x987, 0x564];

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

    mandate_id.serialize(ref calldata);
    let call = Call {
        to: contract_address_const::<0x4567>(), selector: selector!("execute_mandate"), calldata: calldata.span()
    };
    let mut calls = array![];
    calls.append(call);

    let is_valid = account.__validate__(calls);
    assert_eq!(is_valid, starknet::VALIDATED);
//let is_valid = state.is_valid_signature(hash, bad_signature);
//assert!(is_valid.is_zero(), "Should reject invalid signature");
}
