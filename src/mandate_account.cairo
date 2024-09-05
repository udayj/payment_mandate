// SPDX-License-Identifier: MIT
// Forked from OpenZeppelin Contracts for Cairo v0.14.0 (account/account.cairo)

/// # Account Component with mandate feature
///
/// The Account component enables contracts to behave as accounts with the additional option to setup recurring mandates
#[starknet::component]
pub mod MandateAccountComponent {
    use core::hash::{HashStateExTrait, HashStateTrait};
    use core::num::traits::Zero;
    use core::poseidon::PoseidonTrait;
    use core::ecdsa::recover_public_key;
    use core::traits::TryInto;
    use openzeppelin::account::interface;
    use openzeppelin::account::utils::{MIN_TRANSACTION_VERSION, QUERY_VERSION, QUERY_OFFSET};
    use openzeppelin::account::utils::{execute_calls, is_valid_stark_signature};
    use openzeppelin::introspection::src5::SRC5Component::InternalTrait as SRC5InternalTrait;
    use openzeppelin::introspection::src5::SRC5Component::SRC5Impl;
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::token::erc20::interface::{IERC20DispatcherTrait, IERC20Dispatcher};
    use starknet::account::Call;
    use starknet::get_caller_address;
    use starknet::get_contract_address;
    use starknet::get_tx_info;
    use starknet::get_block_timestamp;
    use payment_mandate::interfaces::imandate::IPaymentMandate;
    use payment_mandate::types::common::{Mandate, Date};
    use payment_mandate::utils::get_date;

    #[storage]
    struct Storage {
        Account_public_key: felt252,
        Account_mandates: LegacyMap<u128,Mandate>,
        Account_num_mandates: u128,
        Account_mandate_execution_status: LegacyMap<(u128, u64, u64, u64), bool>
    }

    #[event]
    #[derive(Drop, PartialEq, starknet::Event)]
    pub enum Event {
        OwnerAdded: OwnerAdded,
        OwnerRemoved: OwnerRemoved
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    pub struct OwnerAdded {
        #[key]
        pub new_owner_guid: felt252
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    pub struct OwnerRemoved {
        #[key]
        pub removed_owner_guid: felt252
    }

    pub mod Errors {
        pub const INVALID_CALLER: felt252 = 'Account: invalid caller';
        pub const INVALID_SIGNATURE: felt252 = 'Account: invalid signature';
        pub const INVALID_TX_VERSION: felt252 = 'Account: invalid tx version';
        pub const UNAUTHORIZED: felt252 = 'Account: unauthorized';
        pub const INVALID_MANDATE_ID: felt252 = 'Account: invalid mandate id';
        pub const MANDATE_INACTIVE: felt252 = 'Account: mandate removed';
        pub const MANDATE_EXPIRED: felt252 = 'Account: mandate expired';
        pub const INVALID_MANDATE_DAY: felt252 = 'Account: invalid mandate day';
        pub const MANDATE_ALREADY_EXECUTED: felt252 = 'Account: mandate cycle executed';
    }

    //
    // External
    //

    #[embeddable_as(MandateImpl)]
    impl PaymentMandate<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of IPaymentMandate<ComponentState<TContractState>> {

        fn add_mandate(ref self: ComponentState<TContractState>, mandate: Mandate) -> u128 {

            self.assert_only_self();
            let num_mandates = self.Account_num_mandates.read();
            self.Account_mandates.write(num_mandates, mandate);
            self.Account_num_mandates.write(num_mandates+1);
            
            return num_mandates;
        }

        fn remove_mandate(ref self: ComponentState<TContractState>, mandate_id: u128) {

            self.assert_only_self();
            let mut mandate = self.Account_mandates.read(mandate_id);
            //mandate.status = false;
            self.Account_mandates.write(mandate_id, mandate);

        }

        fn execute_mandate(ref self: ComponentState<TContractState>, mandate_id: u128) {
            
            self.assert_only_self();

            assert(mandate_id < self.Account_num_mandates.read(), Errors::INVALID_MANDATE_ID);
            // Check whether mandate can be executed
            let mut mandate:Mandate = self.Account_mandates.read(mandate_id);

            assert(mandate.is_active, Errors::MANDATE_INACTIVE);
            let current_timestamp = get_block_timestamp();
            assert(current_timestamp <= mandate.valid_till_timestamp, Errors::MANDATE_EXPIRED);
            
            let mandate_date = get_date(current_timestamp);

            assert(mandate_date.day == mandate.day_of_month, Errors::INVALID_MANDATE_DAY );
            assert(
                !self.Account_mandate_execution_status.read(
                    (mandate_id, mandate_date.year, mandate_date.month, mandate_date.day)),
                Errors::MANDATE_ALREADY_EXECUTED
            );
            
            let erc20_currency = IERC20Dispatcher {contract_address: mandate.currency_address};
            erc20_currency.transfer(mandate.pay_to, mandate.amount);
            mandate.num_executed = mandate.num_executed + 1;
            mandate.last_executed_timestamp = get_block_timestamp();
            self.Account_mandates.write(mandate_id, mandate);
            self.Account_mandate_execution_status.write(
                (mandate_id, mandate_date.year, mandate_date.month, mandate_date.day), true
            );
        }
    }

    #[embeddable_as(SRC6Impl)]
    impl SRC6<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::ISRC6<ComponentState<TContractState>> {
        /// Executes a list of calls from the account.
        ///
        /// Requirements:
        ///
        /// - The transaction version must be greater than or equal to `MIN_TRANSACTION_VERSION`.
        /// - If the transaction is a simulation (version than `QUERY_OFFSET`), it must be
        /// greater than or equal to `QUERY_OFFSET` + `MIN_TRANSACTION_VERSION`.
        fn __execute__(
            self: @ComponentState<TContractState>, mut calls: Array<Call>
        ) -> Array<Span<felt252>> {
            // Avoid calls from other contracts
            // https://github.com/OpenZeppelin/cairo-contracts/issues/344
            let sender = get_caller_address();
            assert(sender.is_zero(), Errors::INVALID_CALLER);

            // Check tx version
            let tx_info = get_tx_info().unbox();
            let tx_version: u256 = tx_info.version.into();
            // Check if tx is a query
            if (tx_version >= QUERY_OFFSET) {
                assert(
                    QUERY_OFFSET + MIN_TRANSACTION_VERSION <= tx_version, Errors::INVALID_TX_VERSION
                );
            } else {
                assert(MIN_TRANSACTION_VERSION <= tx_version, Errors::INVALID_TX_VERSION);
            }

            execute_calls(calls)
        }

        /// Verifies the validity of the signature for the current transaction.
        /// This function is used by the protocol to verify `invoke` transactions.
        fn __validate__(self: @ComponentState<TContractState>, mut calls: Array<Call>) -> felt252 {
            self.validate_transaction_with_mandate(calls)
        }

        /// Verifies that the given signature is valid for the given hash.
        fn is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            if self._is_valid_signature(hash, signature.span()) {
                starknet::VALIDATED
            } else {
                0
            }
        }
    }

    #[embeddable_as(DeclarerImpl)]
    impl Declarer<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::IDeclarer<ComponentState<TContractState>> {
        /// Verifies the validity of the signature for the current transaction.
        /// This function is used by the protocol to verify `declare` transactions.
        fn __validate_declare__(
            self: @ComponentState<TContractState>, class_hash: felt252
        ) -> felt252 {
            self.validate_transaction()
        }
    }

    #[embeddable_as(DeployableImpl)]
    impl Deployable<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::IDeployable<ComponentState<TContractState>> {
        /// Verifies the validity of the signature for the current transaction.
        /// This function is used by the protocol to verify `deploy_account` transactions.
        fn __validate_deploy__(
            self: @ComponentState<TContractState>,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: felt252
        ) -> felt252 {
            self.validate_transaction()
        }
    }

    #[embeddable_as(PublicKeyImpl)]
    impl PublicKey<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::IPublicKey<ComponentState<TContractState>> {
        /// Returns the current public key of the account.
        fn get_public_key(self: @ComponentState<TContractState>) -> felt252 {
            self.Account_public_key.read()
        }

        /// Sets the public key of the account to `new_public_key`.
        ///
        /// Requirements:
        ///
        /// - The caller must be the contract itself.
        /// - The signature must be valid for the new owner.
        ///
        /// Emits both an `OwnerRemoved` and an `OwnerAdded` event.
        fn set_public_key(
            ref self: ComponentState<TContractState>,
            new_public_key: felt252,
            signature: Span<felt252>
        ) {
            self.assert_only_self();

            let current_owner = self.Account_public_key.read();
            self.assert_valid_new_owner(current_owner, new_public_key, signature);

            self.emit(OwnerRemoved { removed_owner_guid: current_owner });
            self._set_public_key(new_public_key);
        }
    }

    /// Adds camelCase support for `ISRC6`.
    #[embeddable_as(SRC6CamelOnlyImpl)]
    impl SRC6CamelOnly<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::ISRC6CamelOnly<ComponentState<TContractState>> {
        fn isValidSignature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            SRC6::is_valid_signature(self, hash, signature)
        }
    }

    /// Adds camelCase support for `PublicKeyTrait`.
    #[embeddable_as(PublicKeyCamelImpl)]
    impl PublicKeyCamel<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::IPublicKeyCamel<ComponentState<TContractState>> {
        fn getPublicKey(self: @ComponentState<TContractState>) -> felt252 {
            self.Account_public_key.read()
        }

        fn setPublicKey(
            ref self: ComponentState<TContractState>,
            newPublicKey: felt252,
            signature: Span<felt252>
        ) {
            PublicKey::set_public_key(ref self, newPublicKey, signature);
        }
    }

    #[embeddable_as(AccountMixinImpl)]
    impl AccountMixin<
        TContractState,
        +HasComponent<TContractState>,
        impl SRC5: SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::AccountABI<ComponentState<TContractState>> {
        // ISRC6
        fn __execute__(
            self: @ComponentState<TContractState>, calls: Array<Call>
        ) -> Array<Span<felt252>> {
            SRC6::__execute__(self, calls)
        }

        fn __validate__(self: @ComponentState<TContractState>, calls: Array<Call>) -> felt252 {
            SRC6::__validate__(self, calls)
        }

        fn is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            SRC6::is_valid_signature(self, hash, signature)
        }

        // ISRC6CamelOnly
        fn isValidSignature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            SRC6CamelOnly::isValidSignature(self, hash, signature)
        }

        // IDeclarer
        fn __validate_declare__(
            self: @ComponentState<TContractState>, class_hash: felt252
        ) -> felt252 {
            Declarer::__validate_declare__(self, class_hash)
        }

        // IDeployable
        fn __validate_deploy__(
            self: @ComponentState<TContractState>,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: felt252
        ) -> felt252 {
            Deployable::__validate_deploy__(self, class_hash, contract_address_salt, public_key)
        }

        // IPublicKey
        fn get_public_key(self: @ComponentState<TContractState>) -> felt252 {
            PublicKey::get_public_key(self)
        }

        fn set_public_key(
            ref self: ComponentState<TContractState>,
            new_public_key: felt252,
            signature: Span<felt252>
        ) {
            PublicKey::set_public_key(ref self, new_public_key, signature);
        }

        // IPublicKeyCamel
        fn getPublicKey(self: @ComponentState<TContractState>) -> felt252 {
            PublicKeyCamel::getPublicKey(self)
        }

        fn setPublicKey(
            ref self: ComponentState<TContractState>,
            newPublicKey: felt252,
            signature: Span<felt252>
        ) {
            PublicKeyCamel::setPublicKey(ref self, newPublicKey, signature);
        }

        // ISRC5
        fn supports_interface(
            self: @ComponentState<TContractState>, interface_id: felt252
        ) -> bool {
            let src5 = get_dep_component!(self, SRC5);
            src5.supports_interface(interface_id)
        }
    }

    //
    // Internal
    //

    #[generate_trait]
    pub impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        impl SRC5: SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of InternalTrait<TContractState> {
        /// Initializes the account by setting the initial public key
        /// and registering the ISRC6 interface Id.
        fn initializer(ref self: ComponentState<TContractState>, public_key: felt252) {
            let mut src5_component = get_dep_component_mut!(ref self, SRC5);
            src5_component.register_interface(interface::ISRC6_ID);
            self._set_public_key(public_key);
        }

        /// Validates that the caller is the account itself. Otherwise it reverts.
        fn assert_only_self(self: @ComponentState<TContractState>) {
            let caller = get_caller_address();
            let self = get_contract_address();
            assert(self == caller, Errors::UNAUTHORIZED);
        }

        /// Validates that `new_owner` accepted the ownership of the contract.
        ///
        /// WARNING: This function assumes that `current_owner` is the current owner of the contract, and
        /// does not validate this assumption.
        ///
        /// Requirements:
        ///
        /// - The signature must be valid for the new owner.
        fn assert_valid_new_owner(
            self: @ComponentState<TContractState>,
            current_owner: felt252,
            new_owner: felt252,
            signature: Span<felt252>
        ) {
            let message_hash = PoseidonTrait::new()
                .update_with('StarkNet Message')
                .update_with('accept_ownership')
                .update_with(get_contract_address())
                .update_with(current_owner)
                .finalize();

            let is_valid = is_valid_stark_signature(message_hash, new_owner, signature);
            assert(is_valid, Errors::INVALID_SIGNATURE);
        }

        /// Validates the signature for the current transaction.
        /// Returns the short string `VALID` if valid, otherwise it reverts.
        fn validate_transaction_with_mandate(self: @ComponentState<TContractState>, mut tx_calls: Array<Call>) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature;
            let mut calls = tx_calls.span();
            // check for valid signature based on stored account key
            // else check if pub key recovered matches a whitelisted mandate executor public key
            // then check if call is to self only and only to execute_mandate selector
            let owner_sig_valid = self._is_valid_signature(tx_hash, signature);

            if owner_sig_valid {
                return starknet::VALIDATED;
            }

            let valid_length = signature.len() == 2;

            if valid_length {
                let self_address = get_contract_address();
                let mut possible_pub_key_1=0;
                let mut possible_pub_key_2=0;
                let r_possible_pub_key_1 = recover_public_key(tx_hash, *signature.at(0_u32), *signature.at(1_u32), true);
                let r_possible_pub_key_2 = recover_public_key(tx_hash, *signature.at(0_u32), *signature.at(1_u32), false);
                if r_possible_pub_key_1 == Option::None {
                    possible_pub_key_1 == 0;
                }
                else {
                    possible_pub_key_1 = r_possible_pub_key_1.unwrap();
                }

                if r_possible_pub_key_2 == Option::None {
                    possible_pub_key_2 == 0;
                }
                else {
                    possible_pub_key_2 = r_possible_pub_key_2.unwrap();
                }
                assert(possible_pub_key_1.is_non_zero() || possible_pub_key_2.is_non_zero(), Errors::INVALID_SIGNATURE);

                let mut actual_public_key:felt252 = 0;
                while let Option::Some(call) = calls.pop_front() {
                    assert(*call.to == self_address, 'MANDATE CALL NOT TO SELF');
                    assert(*call.selector == selector!("execute_mandate"), 'INVALID MANDATE CALL');
                    let mandate_id:u128 = (*((*call.calldata).at(0))).try_into().unwrap();
                    let mandate:Mandate = self.Account_mandates.read(mandate_id);

                    if actual_public_key !=0 && actual_public_key!=mandate.executor_public_key {
                        // Calls to mandates with different public keys
                        assert(false, Errors::INVALID_SIGNATURE);
                    }
                    if actual_public_key == 0 {
                        actual_public_key = mandate.executor_public_key;
                    }
                    assert(actual_public_key == possible_pub_key_1 || actual_public_key == possible_pub_key_2,  Errors::INVALID_SIGNATURE);

                };
                return starknet::VALIDATED;
            }
            assert(false, Errors::INVALID_SIGNATURE);
            starknet::VALIDATED
        }

        fn validate_transaction(self: @ComponentState<TContractState>) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature;

            assert(self._is_valid_signature(tx_hash, signature), Errors::INVALID_SIGNATURE);
            starknet::VALIDATED
        }

        /// Sets the public key without validating the caller.
        /// The usage of this method outside the `set_public_key` function is discouraged.
        ///
        /// Emits an `OwnerAdded` event.
        fn _set_public_key(ref self: ComponentState<TContractState>, new_public_key: felt252) {
            self.Account_public_key.write(new_public_key);
            self.emit(OwnerAdded { new_owner_guid: new_public_key });
        }

        /// Returns whether the given signature is valid for the given hash
        /// using the account's current public key.
        fn _is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Span<felt252>
        ) -> bool {
            let public_key = self.Account_public_key.read();
            is_valid_stark_signature(hash, public_key, signature)
        }
    }
}