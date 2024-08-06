#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

mod proxy;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use multiversx_sc_snippets::multiversx_sc_scenario::api::VMHooksApi;
use multiversx_sc_snippets::sdk;
use multiversx_sc_snippets::{imports::*, multiversx_sc_scenario::meta::contract};
use reqwest::Client;
use reqwest::Error;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{Read, Write},
    panic,
    path::Path,
    process,
    str::FromStr,
};
use tokio::{
    task,
    time::{sleep, Duration},
};

//const GATEWAY: &str = sdk::gateway::DEVNET_GATEWAY;
const GATEWAY: &str = "http://localhost:8085";
const STATE_FILE: &str = "state.toml";
const TKN_IDENTIFIER: &str = "MBLK-9e6889";
const TKN_IDENTIFIER2: &str = "AAA-004f5b";
const SIM_ADDR: &str = "erd14238csp6377ufp762szh5zytqu4cx8vks2f6rgg5t05n9fq2r8lqx0pfzk";
const EASTER_EGG: &str = "aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1zRTJGblNnektoNA==";

fn parse_u64_arg(arg: Option<String>, arg_name: &str) -> u64 {
    arg.expect(&format!("{} argument is required", arg_name))
        .parse::<u64>()
        .unwrap_or_else(|_| {
            eprintln!("Failed to parse {} as u64", arg_name);
            process::exit(1);
        })
}

fn parse_address(arg: Option<String>) -> Address {
    let address_str = arg.expect("address argument is required");
    address_from_str(&address_str)
}

fn parse_token_payments() -> TokenPayments {
    let args: Vec<String> = std::env::args().skip(2).collect();

    let mut token_ids = Vec::new();
    let mut token_nonces = Vec::new();
    let mut token_amounts = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if i + 2 >= args.len() {
            eprintln!("Insufficient arguments for token payment details");
            std::process::exit(1);
        }

        let token_id = args[i].clone();
        let nonce = args[i + 1].parse::<u64>().unwrap_or_else(|_| {
            eprintln!("Failed to parse nonce as u64: {}", args[i + 1]);
            std::process::exit(1);
        });
        let amount = args[i + 2].parse::<u128>().unwrap_or_else(|_| {
            eprintln!("Failed to parse amount as u128: {}", args[i + 2]);
            std::process::exit(1);
        });

        token_ids.push(token_id);
        token_nonces.push(nonce);
        token_amounts.push(amount);

        i += 3;
    }

    TokenPayments {
        token_ids,
        token_nonces,
        token_amounts,
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let mut args = std::env::args();
    let _ = wallets().await;
    let _ = args.next(); // Skip the first argument which is the program name

    let cmd = args.next().expect("at least one argument required");
    let mut interact = ContractInteract::new().await;

    match cmd.as_str() {
        "deploy" => {
            let unbond_period = parse_u64_arg(args.next(), "unbond period");
            interact.deploy(unbond_period).await
        }
        "upgrade" => {
            let unbond_period = parse_u64_arg(args.next(), "unbond period");
            interact.upgrade(unbond_period).await
        }
        "wallets" => {
            let result = wallets().await;
            println!("Wallets: {:?}", result);
        }
        "set_unbond_period" => {
            let unbond_period = parse_u64_arg(args.next(), "unbond period");
            interact.set_unbond_period(unbond_period).await
        }
        "whitelist_token" => {
            let token = args.next().expect("token argument is required");
            interact.whitelist_token(&token).await
        }
        "token_whitelist" => interact.token_whitelist().await,
        "esdt" => {
            let addr = args.next().expect("wallet address is required");
            let _ = get_addr_esdt(&addr).await;
        }
        "keys" => {
            let addr = args.next().expect("wallet address is required");
            let _ = get_addr_keys(&addr).await;
        }
        "blacklist_token" => {
            let token = args.next().expect("token argument is required");
            interact.blacklist_token(&token).await
        }
        "lock" => {
            let tokens = parse_token_payments();
            interact.lock(tokens).await
        }
        "unlock" => {
            let tokens = parse_token_payments();
            interact.unlock(tokens).await
        }
        "unbond" => {
            let token_id = args.next().expect("token ID argument is required");
            interact.unbond(&token_id).await
        }
        "lockedTokenAmounts" => {
            let address = parse_address(args.next());
            interact.locked_token_by_address(&address).await
        }
        "unlockedTokenEpochs" => {
            let address = parse_address(args.next());
            let token = args.next().expect("token argument is required");
            interact.unlocked_token_epochs(&address, &token).await
        }
        "unlockedTokenAmounts" => {
            let address = parse_address(args.next());
            let token = args.next().expect("token argument is required");
            let epoch = parse_u64_arg(args.next(), "epoch");
            interact
                .unlocked_token_amounts(&address, &token, epoch)
                .await
        }
        "processTransaction" => {
            let hash = args.next().expect("tx_hash argument is required");
            let _ = process_transaction(&hash).await;
        }
        "generateEpochs" => {
            let epochNr = args.next().expect("epochNr argument is required");
            let _ = generate_blocks_until_epoch(&epochNr).await;
        }
        _ => panic!("unknown command: {}", &cmd),
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    contract_address: Option<Bech32Address>,
}

impl State {
    // Deserializes state from file
    pub fn load_state() -> Self {
        if Path::new(STATE_FILE).exists() {
            let mut file = std::fs::File::open(STATE_FILE).unwrap();
            let mut content = String::new();
            file.read_to_string(&mut content).unwrap();
            toml::from_str(&content).unwrap()
        } else {
            Self::default()
        }
    }

    /// Sets the contract address
    pub fn set_address(&mut self, address: Bech32Address) {
        self.contract_address = Some(address);
    }

    /// Returns the contract address
    pub fn current_address(&self) -> &Bech32Address {
        self.contract_address
            .as_ref()
            .expect("no known contract, deploy first")
    }
}

impl Drop for State {
    // Serializes state to file
    fn drop(&mut self) {
        let serialized_state = toml::to_string(self).unwrap();

        // Only write to the file if the serialized state is not empty
        if !serialized_state.is_empty() {
            let mut file = std::fs::File::create(STATE_FILE).unwrap();
            file.write_all(serialized_state.as_bytes()).unwrap();
        } else {
            println!("Serialized state is empty, not writing to file.");
        }
    }
}

struct TokenPayments {
    token_ids: Vec<String>,
    token_nonces: Vec<u64>,
    token_amounts: Vec<u128>,
}

impl TokenPayments {
    fn new() -> Self {
        TokenPayments {
            token_ids: Vec::new(),
            token_nonces: Vec::new(),
            token_amounts: Vec::new(),
        }
    }

    fn add(&mut self, token_id: String, token_nonce: u64, token_amount: u128) {
        self.token_ids.push(token_id);
        self.token_nonces.push(token_nonce);
        self.token_amounts.push(token_amount);
    }
}

struct ContractInteract {
    interactor: Interactor,
    wallet_address: Address,
    contract_code: BytesValue,
    state: State,
}

impl ContractInteract {
    async fn new() -> Self {
        let mut interactor = Interactor::new(GATEWAY).await;
        let wallet_address = interactor.register_wallet(Wallet::from_pem_file("/home/justeatanapple/liquid-locking/liquid-locking/interactor/simulationWallet.pem").unwrap());

        let contract_code = BytesValue::interpret_from(
            "mxsc:../output/liquid-locking.mxsc.json",
            &InterpreterContext::default(),
        );

        ContractInteract {
            interactor,
            wallet_address,
            contract_code,
            state: State::load_state(),
        }
    }

    async fn deploy(&mut self, unbond_period: u64) {
        let new_address = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .gas(35_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .init(unbond_period)
            .code(&self.contract_code)
            .returns(ReturnsNewAddress)
            .prepare_async()
            .run()
            .await;

        // let _ = process_transaction("").await;

        let new_address_bech32 = bech32::encode(&new_address);
        self.state.set_address(Bech32Address::from_bech32_string(
            new_address_bech32.clone(),
        ));

        println!("New address: {new_address_bech32}");
    }

    async fn upgrade(&mut self, unbond_period: u64) {
        let state_address = self.state.current_address();

        let response = self
            .interactor
            .tx()
            .to(state_address)
            .from(&self.wallet_address)
            .gas(35_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .upgrade(unbond_period)
            .code(&self.contract_code)
            .code_metadata(CodeMetadata::UPGRADEABLE)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn set_unbond_period(&mut self, unbond_period: u64) {
        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(35_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .set_unbond_period(unbond_period)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn whitelist_token(&mut self, token: &str) {
        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(30_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .whitelist_token(TokenIdentifier::from(token))
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn blacklist_token(&mut self, token: &str) {
        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(30_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .blacklist_token(TokenIdentifier::from(token))
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn lock(&mut self, tokens: TokenPayments) {
        let mut tokenPayments = ManagedVec::new();

        for i in 0..tokens.token_ids.len() {
            let aux = EsdtTokenPayment::new(
                TokenIdentifier::from(&tokens.token_ids[i].to_string()),
                tokens.token_nonces[i],
                BigUint::from(tokens.token_amounts[i]),
            );

            tokenPayments.push(aux);
        }

        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(40_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .lock()
            //.single_esdt(&TokenIdentifier::from(token_id), token_nonce, &BigUint::from(token_amount))
            //.payment((TokenIdentifier::from(token_id), token_nonce, token_amount))
            .payment(tokenPayments)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Lock Result: {response:?}");
    }

    async fn unlock(&mut self, tokens: TokenPayments) {
        let mut tokenPayments = ManagedVec::new();

        for i in 0..tokens.token_ids.len() {
            let aux = EsdtTokenPayment::new(
                TokenIdentifier::from(&tokens.token_ids[i].to_string()),
                tokens.token_nonces[i],
                BigUint::from(tokens.token_amounts[i]),
            );

            tokenPayments.push(aux);
        }

        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(30_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .unlock(tokenPayments)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Unlock Result: {response:?}");
    }

    async fn unbond(&mut self, token_id: &str) {
        let tokens = ManagedVec::from_single_item(TokenIdentifier::from(token_id));

        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(40_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .unbond(tokens)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Unbond Result: {response:?}");
    }

    async fn locked_token_by_address(&mut self, address: &Address) {
        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .locked_token_amounts_by_address(address)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn unlocked_token_by_address(&mut self, address: &Address) {
        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .unlocked_token_by_address(address)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn locked_tokens(&mut self) {
        let address = &self.wallet_address;

        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .locked_tokens(address)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Locked Result: {result_value:?}");
    }

    async fn unlocked_tokens(&mut self) {
        let address = &self.wallet_address;

        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .unlocked_tokens(address)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Unlocked Tokens: {result_value:?}");
    }

    async fn token_whitelist(&mut self) {
        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .token_whitelist()
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Token Whitelist: {result_value:?}");
    }

    async fn unbond_period(&mut self) {
        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .unbond_period()
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Unbond Period: {result_value:?}");
    }

    async fn unlocked_token_epochs(&mut self, address: &Address, token: &str) {
        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .unlocked_token_epochs(address, TokenIdentifier::from(token))
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn unlocked_token_amounts(&mut self, address: &Address, token: &str, epoch: u64) {
        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .unlocked_token_amounts(address, TokenIdentifier::from(token), epoch)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }
}

fn denominate_value(input: u128) -> u128 {
    input * 10u128.pow(18)
}

fn nominate_value(input: u128) -> u128 {
    input / 10u128.pow(18)
}

fn address_from_str(input: &str) -> Address {
    let address = bech32::decode(input);
    address
}

#[tokio::test]
async fn test_deploy() {
    let mut contract_interactor = ContractInteract::new().await;

    let _ = contract_interactor.deploy(7u64).await;
    let aux = contract_interactor.state.current_address();

    println!("SC Address: {aux:?}");
    contract_interactor.unbond_period().await;
}

#[tokio::test]
async fn test_upgrade() {
    let mut contract_interactor = ContractInteract::new().await;

    let aux = contract_interactor.state.current_address();

    contract_interactor.upgrade(6u64).await;
    contract_interactor.unbond_period().await;
}

#[tokio::test]
async fn test_whitelist() {
    let mut contract_interactor = ContractInteract::new().await;

    let MY_TOKEN = String::from(TKN_IDENTIFIER);
    contract_interactor.whitelist_token(&MY_TOKEN).await;

    contract_interactor.token_whitelist().await;
}

#[tokio::test]
async fn test_blacklist() {
    let mut contract_interactor = ContractInteract::new().await;

    let MY_TOKEN = String::from(TKN_IDENTIFIER);
    contract_interactor.blacklist_token(&MY_TOKEN).await;

    println!("Whitelisted Tokens:");
    contract_interactor.token_whitelist().await;
}

#[tokio::test]
async fn test_lock() {
    let mut contract_interactor = ContractInteract::new().await;

    let mut payment = TokenPayments::new();

    payment.add(String::from(TKN_IDENTIFIER), 0u64, denominate_value(15));
    payment.add(String::from(TKN_IDENTIFIER), 0u64, denominate_value(20));

    contract_interactor.lock(payment).await;
    contract_interactor.locked_tokens().await;
}

#[tokio::test]
async fn test_unlock() {
    let mut contract_interactor = ContractInteract::new().await;

    let mut payment = TokenPayments::new();

    payment.add(String::from(TKN_IDENTIFIER), 0u64, denominate_value(15));
    payment.add(String::from(TKN_IDENTIFIER), 0u64, denominate_value(20));

    contract_interactor.unlock(payment).await;
}

#[tokio::test]
async fn test_unbond() {
    let mut contract_interactor = ContractInteract::new().await;

    contract_interactor.unbond(TKN_IDENTIFIER).await;
}

#[tokio::test]
async fn happy_path() {
    let mut contract_interactor = ContractInteract::new().await;

    println!("############ Deploying contract with initial value 5 ############");
    let _ = contract_interactor.deploy(5u64).await;
    println!("############ END ############");

    let wallet_address = contract_interactor.wallet_address.clone();
    println!("Wallet address: {:?}", wallet_address);

    let MY_TOKEN = String::from(TKN_IDENTIFIER);

    println!("############ Whitelisting token: {} ############", MY_TOKEN);
    contract_interactor.whitelist_token(&MY_TOKEN).await;
    println!("############ END ############");

    println!("############ Fetching token whitelist ############");
    contract_interactor.token_whitelist().await;
    println!("############ END ############");

    let mut lock_payment = TokenPayments::new();

    println!("############ Adding tokens to lock payment ############");
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR BEFORE payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Locking tokens ############");
    contract_interactor.lock(lock_payment).await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    let mut unlock_payment = TokenPayments::new();

    println!("############ Adding tokens to unlock payment ############");
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Unlocking tokens ############");
    contract_interactor.unlock(unlock_payment).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Fetching unlocked tokens by address ############");
    contract_interactor
        .unlocked_token_by_address(&wallet_address)
        .await;
    println!("############ END ############");

    println!("############ Generating blocks until epoch ??? ############");
    let _ = generate_blocks_until_epoch("15").await;
    println!("############ END ############");

    println!("############ Unbonding tokens ############");
    contract_interactor.unbond(TKN_IDENTIFIER).await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER unbond ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Happy path execution completed ############");
}

#[tokio::test]
async fn unbond_test_without_period_passing() {
    let mut contract_interactor = ContractInteract::new().await;

    println!("############ Deploying contract with initial value 5 ############");
    let _ = contract_interactor.deploy(5u64).await;
    println!("############ END ############");

    let wallet_address = contract_interactor.wallet_address.clone();
    println!("Wallet address: {:?}", wallet_address);

    let MY_TOKEN = String::from(TKN_IDENTIFIER);

    println!("############ Whitelisting token: {} ############", MY_TOKEN);
    contract_interactor.whitelist_token(&MY_TOKEN).await;
    println!("############ END ############");

    println!("############ Fetching token whitelist ############");
    contract_interactor.token_whitelist().await;
    println!("############ END ############");

    let mut lock_payment = TokenPayments::new();

    println!("############ Adding tokens to lock payment ############");
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR BEFORE payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Locking tokens ############");
    contract_interactor.lock(lock_payment).await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    let mut unlock_payment = TokenPayments::new();

    println!("############ Adding tokens to unlock payment ############");
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Unlocking tokens ############");
    contract_interactor.unlock(unlock_payment).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Fetching unlocked tokens by address ############");
    contract_interactor
        .unlocked_token_by_address(&wallet_address)
        .await;
    println!("############ END ############");

    println!("############ Unbonding tokens ############");
    let unbond_result = contract_interactor.unbond(TKN_IDENTIFIER).await;
    // assert!(unbond_result, "Expected unbond to fail but it succeeded");
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER unbond ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");
}

#[tokio::test]
async fn unbond_test_with_period_passing() {
    let mut contract_interactor = ContractInteract::new().await;

    println!("############ Deploying contract with initial value 5 ############");
    let _ = contract_interactor.deploy(5u64).await;
    println!("############ END ############");

    let wallet_address = contract_interactor.wallet_address.clone();
    println!("Wallet address: {:?}", wallet_address);

    let MY_TOKEN = String::from(TKN_IDENTIFIER);

    println!("############ Whitelisting token: {} ############", MY_TOKEN);
    contract_interactor.whitelist_token(&MY_TOKEN).await;
    println!("############ END ############");

    println!("############ Fetching token whitelist ############");
    contract_interactor.token_whitelist().await;
    println!("############ END ############");

    let mut lock_payment = TokenPayments::new();

    println!("############ Adding tokens to lock payment ############");
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR BEFORE payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Locking tokens ############");
    contract_interactor.lock(lock_payment).await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    let mut unlock_payment = TokenPayments::new();

    println!("############ Adding tokens to unlock payment ############");
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Unlocking tokens ############");
    contract_interactor.unlock(unlock_payment).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Fetching unlocked tokens by address ############");
    contract_interactor
        .unlocked_token_by_address(&wallet_address)
        .await;
    println!("############ END ############");

    println!("############ Generating blocks until epoch ??? ############");
    let _ = generate_blocks_until_epoch("30").await;
    println!("############ END ############");

    println!("############ Unbonding tokens ############");
    let unbond_result = contract_interactor.unbond(TKN_IDENTIFIER).await;
    println!("WATAFAC: {:?}", unbond_result);
    // assert!(unbond_result, "Expected unbond to fail but it succeeded");
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER unbond ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");
}

#[tokio::test]
async fn unbond_test_with_invalid_token() {
    let mut contract_interactor = ContractInteract::new().await;

    println!("############ Deploying contract with initial value 5 ############");
    let _ = contract_interactor.deploy(5u64).await;
    println!("############ END ############");

    let wallet_address = contract_interactor.wallet_address.clone();
    println!("Wallet address: {:?}", wallet_address);

    let MY_TOKEN = String::from(TKN_IDENTIFIER);

    println!("############ Whitelisting tokens: {} {} ############", MY_TOKEN, "TTTT-205c65");
    contract_interactor.whitelist_token(&MY_TOKEN).await;
    contract_interactor.whitelist_token("TTTT-205c65").await;
    println!("############ END ############");

    println!("############ Fetching token whitelist ############");
    contract_interactor.token_whitelist().await;
    println!("############ END ############");

    let mut lock_payment = TokenPayments::new();

    println!("############ Adding tokens to lock payment ############");
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR BEFORE payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Locking tokens ############");
    contract_interactor.lock(lock_payment).await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    let mut unlock_payment = TokenPayments::new();

    println!("############ Adding tokens to unlock payment ############");
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Unlocking tokens ############");
    contract_interactor.unlock(unlock_payment).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Fetching unlocked tokens by address ############");
    contract_interactor
        .unlocked_token_by_address(&wallet_address)
        .await;
    println!("############ END ############");

    println!("############ Generating blocks until epoch ??? ############");
    let _ = generate_blocks_until_epoch("45").await;
    println!("############ END ############");

    println!("############ Unbonding tokens ############");
    let unbond_result = contract_interactor.unbond("TTTT-205c65").await;
    // assert!(unbond_result, "Expected unbond to fail but it succeeded");
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER unbond ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");
}


#[tokio::test]
async fn unbond_test_checking_storage() {
    let mut contract_interactor = ContractInteract::new().await;

    println!("############ Deploying contract with initial value 5 ############");
    let _ = contract_interactor.deploy(5u64).await;
    println!("############ END ############");

    let wallet_address = contract_interactor.wallet_address.clone();
    println!("Wallet address: {:?}", wallet_address);

    let MY_TOKEN = String::from(TKN_IDENTIFIER);

    println!("############ Whitelisting token: {} ############", MY_TOKEN);
    contract_interactor.whitelist_token(&MY_TOKEN).await;
    println!("############ END ############");

    println!("############ Fetching token whitelist ############");
    contract_interactor.token_whitelist().await;
    println!("############ END ############");

    let mut lock_payment = TokenPayments::new();

    println!("############ Adding tokens to lock payment ############");
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR BEFORE payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Locking tokens ############");
    contract_interactor.lock(lock_payment).await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    let mut unlock_payment = TokenPayments::new();

    println!("############ Adding tokens to unlock payment ############");
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Fetching locked tokens BEFORE unlock ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Unlocking tokens ############");
    contract_interactor.unlock(unlock_payment).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens BEFORE unbond ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Fetching unlocked tokens by address ############");
    contract_interactor
        .unlocked_token_by_address(&wallet_address)
        .await;
    println!("############ END ############");

    println!("############ Generating blocks until epoch ??? ############");
    let _ = generate_blocks_until_epoch("60").await;
    println!("############ END ############");

    println!("############ Unbonding tokens ############");
    contract_interactor.unbond(TKN_IDENTIFIER).await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER unbond ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens AFTER unbond ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

}

#[tokio::test]
async fn double_unbond_test() {
    let mut contract_interactor = ContractInteract::new().await;

    println!("############ Deploying contract with initial value 5 ############");
    let _ = contract_interactor.deploy(5u64).await;
    println!("############ END ############");

    let wallet_address = contract_interactor.wallet_address.clone();
    println!("Wallet address: {:?}", wallet_address);

    let MY_TOKEN = String::from(TKN_IDENTIFIER);

    println!("############ Whitelisting token: {} ############", MY_TOKEN);
    contract_interactor.whitelist_token(&MY_TOKEN).await;
    println!("############ END ############");

    println!("############ Fetching token whitelist ############");
    contract_interactor.token_whitelist().await;
    println!("############ END ############");

    let mut lock_payment = TokenPayments::new();

    println!("############ Adding tokens to lock payment ############");
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR BEFORE payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Locking tokens ############");
    contract_interactor.lock(lock_payment).await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    let mut unlock_payment = TokenPayments::new();

    println!("############ Adding tokens to unlock payment ############");
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Fetching locked tokens BEFORE unlock ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Unlocking tokens ############");
    contract_interactor.unlock(unlock_payment).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens BEFORE unbond ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Fetching unlocked tokens by address ############");
    contract_interactor
        .unlocked_token_by_address(&wallet_address)
        .await;
    println!("############ END ############");

    println!("############ Generating blocks until epoch ??? ############");
    let _ = generate_blocks_until_epoch("75").await;
    println!("############ END ############");

    println!("############ Unbonding tokens ############");
    contract_interactor.unbond(TKN_IDENTIFIER).await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER unbond ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens AFTER unbond ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Unbonding tokens with storage empty ############");
    contract_interactor.unbond(TKN_IDENTIFIER).await;
    println!("############ END ############");

}

#[tokio::test]
async fn unbond_empty_token() {
    let mut contract_interactor = ContractInteract::new().await;

    println!("############ Deploying contract with initial value 5 ############");
    let _ = contract_interactor.deploy(5u64).await;
    println!("############ END ############");

    let wallet_address = contract_interactor.wallet_address.clone();
    println!("Wallet address: {:?}", wallet_address);

    let MY_TOKEN = String::from(TKN_IDENTIFIER);

    println!("############ Whitelisting token: {} ############", MY_TOKEN);
    contract_interactor.whitelist_token(&MY_TOKEN).await;
    println!("############ END ############");

    println!("############ Fetching token whitelist ############");
    contract_interactor.token_whitelist().await;
    println!("############ END ############");

    let mut lock_payment = TokenPayments::new();

    println!("############ Adding tokens to lock payment ############");
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR BEFORE payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Locking tokens ############");
    contract_interactor.lock(lock_payment).await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    let mut unlock_payment = TokenPayments::new();

    println!("############ Adding tokens to unlock payment ############");
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 500);
    println!("############ END ############");

    println!("############ Fetching locked tokens BEFORE unlock ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Unlocking tokens ############");
    contract_interactor.unlock(unlock_payment).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Fetching unlocked tokens by address ############");
    contract_interactor
        .unlocked_token_by_address(&wallet_address)
        .await;
    println!("############ END ############");

    println!("############ Generating blocks until epoch ??? ############");
    let _ = generate_blocks_until_epoch("90").await;
    println!("############ END ############");

    println!("############ Unbonding tokens ############");
    contract_interactor.unbond("").await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER unbond ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");
}

#[tokio::test]
async fn unbond_multiple_tokens() {
    let mut contract_interactor = ContractInteract::new().await;

    println!("############ Deploying contract with initial value 5 ############");
    let _ = contract_interactor.deploy(5u64).await;
    println!("############ END ############");

    let wallet_address = contract_interactor.wallet_address.clone();
    println!("Wallet address: {:?}", wallet_address);

    let MY_TOKEN = String::from(TKN_IDENTIFIER);
    let MY_TOKEN2 = String::from(TKN_IDENTIFIER2);

    println!("############ Whitelisting tokens: {} {} ############", MY_TOKEN, MY_TOKEN2);
    contract_interactor.whitelist_token(&MY_TOKEN).await;
    contract_interactor.whitelist_token(&MY_TOKEN2).await;
    println!("############ END ############");

    println!("############ Fetching token whitelist ############");
    contract_interactor.token_whitelist().await;
    println!("############ END ############");

    let mut lock_payment = TokenPayments::new();

    println!("############ Adding tokens to lock payment ############");
    lock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    lock_payment.add(String::from(TKN_IDENTIFIER2), 0u64, 500);
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR BEFORE payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Locking tokens ############");
    contract_interactor.lock(lock_payment).await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER payment ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    let mut unlock_payment = TokenPayments::new();

    println!("############ Adding tokens to unlock payment ############");
    unlock_payment.add(String::from(TKN_IDENTIFIER), 0u64, 100);
    unlock_payment.add(String::from(TKN_IDENTIFIER2), 0u64, 500);
    println!("############ END ############");

    println!("############ Fetching locked tokens BEFORE unlock ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Unlocking tokens ############");
    contract_interactor.unlock(unlock_payment).await;
    println!("############ END ############");

    println!("############ Fetching locked tokens ############");
    contract_interactor.locked_tokens().await;
    println!("############ END ############");

    println!("############ Fetching unlocked tokens by address ############");
    contract_interactor
        .unlocked_token_by_address(&wallet_address)
        .await;
    println!("############ END ############");

    println!("############ Generating blocks until epoch ??? ############");
    let _ = generate_blocks_until_epoch("100").await;
    println!("############ END ############");

    println!("############ Unbonding first tokens ############");
    contract_interactor.unbond(TKN_IDENTIFIER).await;
    println!("############ END ############");

    println!("############ Unbonding second tokens ############");
    contract_interactor.unbond(TKN_IDENTIFIER2).await;
    println!("############ END ############");

    println!("############ Getting address ESDT for SIM_ADDR AFTER unbond ############");
    let _ = get_addr_esdt(SIM_ADDR).await;
    println!("############ END ############");
}

#[tokio::test]
async fn get_views() {
    let mut contract_interactor = ContractInteract::new().await;

    println!("Whitelisted Tokens:");
    contract_interactor.token_whitelist().await;
    println!("Locked Tokens:");
    contract_interactor.locked_tokens().await;
    println!("Unlocked Tokens:");
    contract_interactor.unlocked_tokens().await;
    println!("Locked Tokens By Address:");
    contract_interactor
        .locked_token_by_address(&address_from_str(
            SIM_ADDR,
        ))
        .await;
    println!("Unlocked Tokens By Address:");
    contract_interactor
        .unlocked_token_by_address(&address_from_str(
            SIM_ADDR,
        ))
        .await;
    println!("Unlocked Tokens By Epochs:");
    contract_interactor
        .unlocked_token_epochs(
            &address_from_str(SIM_ADDR),
            TKN_IDENTIFIER,
        )
        .await;
    println!("Unlocked Tokens By Amounts:");
    contract_interactor
        .unlocked_token_amounts(
            &address_from_str(SIM_ADDR),
            TKN_IDENTIFIER,
            1961u64,
        )
        .await;

    contract_interactor.set_unbond_period(0u64).await;
    contract_interactor.unbond_period().await;
}

#[tokio::test]
async fn get_network_config() -> Result<(), Error> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:8085/network/config")
        .send()
        .await?;

    if response.status().is_success() {
        println!("Successfully sent GET request!");
        let body = response.text().await?;
        println!("Response: {}", body);
    } else {
        println!("Failed to send GET request. Status: {}", response.status());
    }

    Ok(())
}

#[tokio::test]
async fn get_addr_info() -> Result<(), Error> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:8085/address/erd19yu7mt557kwf0pd9qq4hwtp33mz46d4mk2dzflft0varzsg26qlqy4q8cg")
        .send()
        .await?;

    if response.status().is_success() {
        println!("Successfully sent GET request!");
        let body = response.text().await?;
        println!("Response: {}", body);
    } else {
        println!("Failed to send GET request. Status: {}", response.status());
    }

    Ok(())
}

async fn get_addr_keys(param: &str) -> Result<(), Error> {
    let client = reqwest::Client::new();
    let url = format!("http://localhost:8085/address/{}/keys", param);
    let response = client.get(&url).send().await?;

    if response.status().is_success() {
        println!("Successfully sent GET request!");
        let body = response.text().await?;
        println!("Response: {}", body);
    } else {
        println!("Failed to send GET request. Status: {}", response.status());
    }

    Ok(())
}

async fn get_addr_esdt(param: &str) -> Result<(), Error> {
    let client = reqwest::Client::new();
    let url = format!("http://localhost:8085/address/{}/esdt", param);
    let response = client.get(&url).send().await?;

    if response.status().is_success() {
        println!("Successfully sent GET request!");
        let body = response.text().await?;
        println!("Response: {}", body);
    } else {
        println!("Failed to send GET request. Status: {}", response.status());
    }

    Ok(())
}

async fn wallets() -> Result<(), Error> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:8085/simulator/initial-wallets")
        .send()
        .await?;

    if response.status().is_success() {
        println!("Successfully sent GET request!");
        let body = response.text().await?;
        let aux: Value = serde_json::from_str(&body).unwrap();

        let specific_wallet = &aux["data"]["balanceWallets"]["2"];

        // Extract bech32 address and privateKeyHex directly from specific_wallet
        let bech32 = specific_wallet["address"]["bech32"].as_str().unwrap();
        let private_key_hex = specific_wallet["privateKeyHex"].as_str().unwrap();

        // Convert privateKeyHex string to a base64 encoded string
        let private_key_base64 = STANDARD.encode(private_key_hex);

        // Split the base64 string into 64-character lines
        let formatted_key = private_key_base64
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<&str>>()
            .join("\n");

        // Create the content of the .pem file
        let pem_content = format!(
            "-----BEGIN PRIVATE KEY for {}-----\n{}\n-----END PRIVATE KEY for {}-----",
            bech32, formatted_key, bech32
        );

        // Write the content to simulationWallet.pem
        let mut file = File::create("simulationWallet.pem").unwrap();
        let mut addr_file = File::create("walletAddress.txt").unwrap();
        addr_file.write_all(bech32.as_bytes()).unwrap();
        file.write_all(pem_content.as_bytes()).unwrap()
    } else {
        println!("Failed to send GET request. Status: {}", response.status());
    }

    Ok(())
}

async fn process_transaction(param: &str) -> Result<(), Error> {
    let client = reqwest::Client::new();
    let url = format!(
        "http://localhost:8085/simulator/generate-blocks-until-transaction-processed/{}",
        param
    );
    let response = client.post(&url).send().await?;

    if response.status().is_success() {
        println!("Successfully sent POST request!");
        let body = response.text().await?;
        println!("Response: {}", body);
    } else {
        println!("Failed to send POST request. Status: {}", response.status());
    }

    Ok(())
}

async fn generate_blocks(param: &str) -> Result<(), Error> {
    let client = reqwest::Client::new();
    let url = format!("http://localhost:8085/simulator/generate-blocks/{}", param);
    let response = client.post(&url).send().await?;

    if response.status().is_success() {
        println!("Successfully sent POST request!");
        let body = response.text().await?;
        println!("Response: {}", body);
    } else {
        println!("Failed to send POST request. Status: {}", response.status());
    }

    Ok(())
}

async fn generate_blocks_until_epoch(param: &str) -> Result<(), Error> {
    let client = reqwest::Client::new();
    let url = format!(
        "http://localhost:8085/simulator/generate-blocks-until-epoch-reached/{}",
        param
    );
    let response = client.post(&url).send().await?;

    if response.status().is_success() {
        println!("Successfully sent POST request!");
        let body = response.text().await?;
        println!("Response: {}", body);
    } else {
        println!("Failed to send POST request. Status: {}", response.status());
    }

    Ok(())
}

async fn generate_blocks_flat() -> Result<(), Error> {
    let client = reqwest::Client::new();
    let response = client
        .post("http://localhost:8085/simulator/generate-blocks/200")
        .send()
        .await?;

    if response.status().is_success() {
        println!("Successfully sent POST request!");
        let body = response.text().await?;
        println!("Response: {}", body);
    } else {
        println!("Failed to send POST request. Status: {}", response.status());
    }

    Ok(())
}

// scenarios for unbond: unbond before period, after period, when epoch is equal to period,
