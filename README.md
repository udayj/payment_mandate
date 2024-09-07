**Recurring Payment Mandates**

Recurring payments are a common need in traditional finance and the real world. They enable use-cases that are ubiquitous, like, 
1. Utility bill payments
2. Payments for subscription services
3. Loan Repayments
4. Insurance premiums
5. Membership Fees
6. SIP for investment purposes

Recurring payment mandates is an attempt to provide a similar level of UX onchain. It utilises native account abstraction on Starknet to setup a variant of session keys called cyclic session keys that enable recurring payments to an authorized service provider.

**How does it work?**

An account owner can add a mandate that includes the public key of the authorized service provider, the amount of tokens that can be transferred, day of the month on which said payment transfer can be done, etc. The service provider can now simply sign and submit a transaction on chain on the said day of the month - the account contract will validate the transaction to be correct (we first check the owner's public key for the signature and then check for validity of the service provider's public key). Thereafter the transaction will be executed on chain with gas fees being paid through the account contract itself. 

Another bonus of this approach is that the user does not need to approve the amount of tokens being transferred in a separate transaction and does not need to trust the service provider for using any token transfer approvals.

A possible variant of this approach can just have a separate function that enables the same functionality but this time the service provider will pay for the gas fees. This might be slightly simpler since we will not check for signatures during validation phase but instead whitelist service provider addresses that can be used to call a separate function in the contract.


