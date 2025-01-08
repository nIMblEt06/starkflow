use starknet::account::Call;
use starknet::ContractAddress;

mod SUPPORTED_TX_VERSION {
    pub const DEPLOY_ACCOUNT: felt252 = 1;
    pub const DECLARE: felt252 = 2;
    pub const INVOKE: felt252 = 1;
}

#[derive(Drop, Serde, starknet::Store)]
pub struct APInfo {
    amount: u256,
    date: u128,
}

#[derive(Drop, Serde, starknet::Store)]
#[allow(starknet::store_no_default_variant)]
pub enum PayStatus {
    Paid,
    Pending,
    Delayed,
}

#[derive(Drop, Serde, starknet::Store)]
pub struct ARInfo {
    amount: u256,
    date: u128,
    status: PayStatus,
}

#[starknet::interface]
trait IAccount<T> {
    fn public_key(self: @T) -> felt252;
    fn supports_interface(self: @T, interface_id: felt252) -> bool;
    fn is_valid_signature(self: @T, hash: felt252, signature: Array<felt252>) -> felt252;
    fn __execute__(self: @T, calls: Array<Call>) -> Array<Span<felt252>>;
    fn __validate__(self: @T, calls: Array<Call>) -> felt252;
    fn __validate_declare__(self: @T, class_hash: felt252) -> felt252;
    fn __validate_deploy__(
        self: @T, class_hash: felt252, salt: felt252, public_key: felt252,
    ) -> felt252;
}

#[starknet::interface]
pub trait IMPCAccount<TContractState> {
    fn add_ap(
        ref self: TContractState,
        contract_address: ContractAddress,
        amount_to_pay: u256,
        date_to_pay: u128,
    ) -> bool;

    fn update_ap(
        ref self: TContractState,
        contract_address: ContractAddress,
        amount_to_pay: u256,
        date_to_pay: u128,
    ) -> bool;

    fn remove_ap(
        ref self: TContractState,
        contract_address: ContractAddress,
    ) -> bool;

    fn add_ar(
        ref self: TContractState,
        contract_address: ContractAddress,
        amount_to_get: u256,
        date_to_get: u128,
    ) -> bool;

    fn update_ar(
        ref self: TContractState,
        contract_address: ContractAddress,
        amount_to_get: u256,
        date_to_get: u128,
        status: PayStatus
    ) -> bool;

    fn remove_ar(
        ref self: TContractState,
        contract_address: ContractAddress,
    );
}


#[starknet::contract(account)]
mod Account {
    use super::{Call, IAccount, SUPPORTED_TX_VERSION};
    use starknet::{get_caller_address, get_tx_info, VALIDATED, ContractAddress};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, StoragePathEntry, Map,
    };
    use super::{APInfo, ARInfo};
    use core::num::traits::Zero;
    use starknet::syscalls::call_contract_syscall;
    use core::ecdsa::check_ecdsa_signature;
    const SIMULATE_TX_VERSION_OFFSET: felt252 = 340282366920938463463374607431768211456; // 2**128
    const SRC6_TRAIT_ID: felt252 =
        1270010605630597976495846281167968799381097569185364931397797212080166453709; // hash of SNIP-6 trait

    #[storage]
    struct Storage {
        public_key: felt252,
        accounts_payable: Map<ContractAddress, APInfo>,
        accounts_receivable: Map<ContractAddress, ARInfo>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252) {
        self.public_key.write(public_key);
    }

    #[abi(embed_v0)]
    impl AccountImpl of IAccount<ContractState> {
        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            let is_valid = self.is_valid_signature_bool(hash, signature.span());
            if is_valid {
                VALIDATED
            } else {
                0
            }
        }

        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            interface_id == SRC6_TRAIT_ID
        }

        fn public_key(self: @ContractState) -> felt252 {
            self.public_key.read()
        }

        fn __execute__(self: @ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
            assert(!calls.is_empty(), 'Account: No call data given');
            self.only_protocol();
            self.only_supported_tx_version(SUPPORTED_TX_VERSION::INVOKE);
            self.execute_multiple_calls(calls)
        }

        fn __validate__(self: @ContractState, calls: Array<Call>) -> felt252 {
            self.only_protocol();
            self.only_supported_tx_version(SUPPORTED_TX_VERSION::INVOKE);
            self.validate_transaction()
        }

        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            self.only_protocol();
            self.only_supported_tx_version(SUPPORTED_TX_VERSION::DECLARE);
            self.validate_transaction()
        }

        fn __validate_deploy__(
            self: @ContractState, class_hash: felt252, salt: felt252, public_key: felt252,
        ) -> felt252 {
            self.only_protocol();
            self.only_supported_tx_version(SUPPORTED_TX_VERSION::DEPLOY_ACCOUNT);
            self.validate_transaction()
        }
    }

    #[abi(embed_v0)]
    impl MPCAccount of super::IMPCAccount<ContractState> {
        fn add_ap(
            ref self: ContractState, contract_address: ContractAddress, amount_to_pay: u256,
            date_to_pay: u128,
        ) -> bool {
            let ap_info = APInfo {
                amount: amount_to_pay,
                date: date_to_pay,
            };
            self.accounts_payable.write(contract_address, ap_info);
            true
        }

        fn update_ap(
            ref self: ContractState, contract_address: ContractAddress, amount_to_pay: u256,
            date_to_pay: u128,
        ) -> bool {
            let ap_info = APInfo {
                amount: amount_to_pay,
                date: date_to_pay,
            };
            self.accounts_payable.write(contract_address, ap_info);
            true
        }

        fn remove_ap(ref self: ContractState, contract_address: ContractAddress) -> bool {
            let ap_info = APInfo {
                amount: 0,
                date: 0,
            };
            self.accounts_payable.write(contract_address, ap_info);
            true
        }

        fn add_ar(
            ref self: ContractState, contract_address: ContractAddress, amount_to_get: u256,
            date_to_get: u128,
        ) -> bool {
            let ar_info = ARInfo {
                amount: amount_to_get,
                date: date_to_get,
                status: super::PayStatus::Pending,
            };
            self.accounts_receivable.write(contract_address, ar_info);
            true
        }

        fn update_ar(
            ref self: ContractState, contract_address: ContractAddress, amount_to_get: u256,
            date_to_get: u128, status: super::PayStatus,
        ) -> bool {
            let ar_info = ARInfo {
                amount: amount_to_get,
                date: date_to_get,
                status,
            };
            self.accounts_receivable.write(contract_address, ar_info);
            true
        }

        fn remove_ar(ref self: ContractState, contract_address: ContractAddress) {
            let ar_info = ARInfo {
                amount: 0,
                date: 0,
                status: super::PayStatus::Paid,
            };
            self.accounts_receivable.write(contract_address, ar_info);
        }
    }

    #[generate_trait]
    impl PrivateImpl of PrivateTrait {
        fn only_protocol(self: @ContractState) {
            let sender = get_caller_address();
            assert(sender.is_zero(), 'Account: invalid caller');
        }

        fn is_valid_signature_bool(
            self: @ContractState, hash: felt252, signature: Span<felt252>,
        ) -> bool {
            let is_valid_length = signature.len() == 2_u32;

            if !is_valid_length {
                return false;
            }

            check_ecdsa_signature(
                hash, self.public_key.read(), *signature.at(0_u32), *signature.at(1_u32),
            )
        }

        fn validate_transaction(self: @ContractState) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature;

            let is_valid = self.is_valid_signature_bool(tx_hash, signature);
            assert(is_valid, 'Account: Incorrect tx signature');
            VALIDATED
        }

        fn execute_single_call(self: @ContractState, call: Call) -> Span<felt252> {
            let Call { to, selector, calldata } = call;
            call_contract_syscall(to, selector, calldata).unwrap()
        }

        fn execute_multiple_calls(
            self: @ContractState, mut calls: Array<Call>,
        ) -> Array<Span<felt252>> {
            let mut res = ArrayTrait::new();
            loop {
                match calls.pop_front() {
                    Option::Some(call) => {
                        let _res = self.execute_single_call(call);
                        res.append(_res);
                    },
                    Option::None(_) => { break (); },
                };
            };
            res
        }

        fn only_supported_tx_version(self: @ContractState, supported_tx_version: felt252) {
            let tx_info = get_tx_info().unbox();
            let version = tx_info.version;
            assert(
                version == supported_tx_version || version == SIMULATE_TX_VERSION_OFFSET
                    + supported_tx_version,
                'Account: Unsupported tx version',
            );
        }
    }
}
