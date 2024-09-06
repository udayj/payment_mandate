#[starknet::contract(account)]
pub(crate) mod MandateAccountMock {
    use payment_mandate::mandate_account::MandateAccountComponent;
    use openzeppelin::introspection::src5::SRC5Component;

    component!(path: MandateAccountComponent, storage: account, event: AccountEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    // Account
    #[abi(embed_v0)]
    impl MandateImpl = MandateAccountComponent::MandateImpl<ContractState>;

    #[abi(embed_v0)]
    impl SRC6Impl = MandateAccountComponent::SRC6Impl<ContractState>;
    #[abi(embed_v0)]
    impl SRC6CamelOnlyImpl =
        MandateAccountComponent::SRC6CamelOnlyImpl<ContractState>;
    #[abi(embed_v0)]
    impl DeclarerImpl = MandateAccountComponent::DeclarerImpl<ContractState>;
    #[abi(embed_v0)]
    impl DeployableImpl = MandateAccountComponent::DeployableImpl<ContractState>;
    impl AccountInternalImpl = MandateAccountComponent::InternalImpl<ContractState>;

    // SCR5
    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        account: MandateAccountComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: MandateAccountComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252) {
        self.account.initializer(public_key);
    }
}
