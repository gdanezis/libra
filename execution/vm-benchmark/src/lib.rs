// Copyright (c) The diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use diem_config::utils::get_genesis_txn;
use diem_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    PrivateKey, SigningKey, Uniform,
};
use diem_logger::prelude::*;
use diem_types::{
    account_address::AccountAddress,
    account_config::{
        testnet_dd_account_address, treasury_compliance_account_address, xus_tag, XUS_NAME,
    },
    chain_id::ChainId,
    transaction::{
        authenticator::AuthenticationKey, RawTransaction, Script, SignedTransaction, Transaction,
    },
};
use diem_vm::DiemVM;

use rand::{rngs::StdRng, SeedableRng};
use std::{path::PathBuf, sync::mpsc};

use transaction_builder::{
    encode_create_parent_vasp_account_script, encode_peer_to_peer_with_metadata_script,
};

use diem_state_view::StateView;
use diem_types::{access_path::AccessPath, transaction::TransactionOutput, write_set::WriteOp};
use diem_vm::VMExecutor;
use std::collections::HashMap;

struct AccountData {
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    address: AccountAddress,
    sequence_number: u64,
}

impl AccountData {
    pub fn auth_key_prefix(&self) -> Vec<u8> {
        AuthenticationKey::ed25519(&self.public_key)
            .prefix()
            .to_vec()
    }
}

struct TransactionGenerator {
    /// The current state of the accounts. The main purpose is to keep track of the sequence number
    /// so generated transactions are guaranteed to be successfully executed.
    accounts: Vec<AccountData>,

    /// Used to mint accounts.
    genesis_key: Ed25519PrivateKey,

    /// For deterministic transaction generation.
    rng: StdRng,

    /// Each generated block of transactions are sent to this channel. Using `SyncSender` to make
    /// sure if execution is slow to consume the transactions, we do not run out of memory.
    block_sender: Option<mpsc::SyncSender<Vec<Transaction>>>,
}

impl TransactionGenerator {
    fn new(
        genesis_key: Ed25519PrivateKey,
        num_accounts: usize,
        block_sender: mpsc::SyncSender<Vec<Transaction>>,
    ) -> Self {
        let seed = [1u8; 32];
        let mut rng = StdRng::from_seed(seed);

        let mut accounts = Vec::with_capacity(num_accounts);
        for _i in 0..num_accounts {
            let private_key = Ed25519PrivateKey::generate(&mut rng);
            let public_key = private_key.public_key();
            let address = diem_types::account_address::from_public_key(&public_key);
            let account = AccountData {
                private_key,
                public_key,
                address,
                sequence_number: 0,
            };
            accounts.push(account);
        }

        Self {
            accounts,
            genesis_key,
            rng,
            block_sender: Some(block_sender),
        }
    }

    fn run(&mut self, init_account_balance: u64, block_size: usize, num_transfer_blocks: usize) {
        self.gen_account_creations(block_size);
        self.gen_mint_transactions(init_account_balance, block_size);
        self.gen_transfer_transactions(block_size, num_transfer_blocks);
    }

    fn gen_account_creations(&self, block_size: usize) {
        let tc_account = treasury_compliance_account_address();

        for (i, block) in self.accounts.chunks(block_size).enumerate() {
            let mut transactions = Vec::with_capacity(block_size);
            for (j, account) in block.iter().enumerate() {
                let txn = create_transaction(
                    tc_account,
                    (i * block_size + j) as u64,
                    &self.genesis_key,
                    self.genesis_key.public_key(),
                    encode_create_parent_vasp_account_script(
                        xus_tag(),
                        0,
                        account.address,
                        account.auth_key_prefix(),
                        vec![],
                        false, /* add all currencies */
                    ),
                );
                transactions.push(txn);
            }

            println!("SEND ACCOUNT CREATE BLOCK");
            self.block_sender
                .as_ref()
                .unwrap()
                .send(transactions)
                .unwrap();
        }
    }

    /// Generates transactions that allocate `init_account_balance` to every account.
    fn gen_mint_transactions(&self, init_account_balance: u64, block_size: usize) {
        let testnet_dd_account = testnet_dd_account_address();

        for (i, block) in self.accounts.chunks(block_size).enumerate() {
            let mut transactions = Vec::with_capacity(block_size);
            for (j, account) in block.iter().enumerate() {
                let txn = create_transaction(
                    testnet_dd_account,
                    (i * block_size + j) as u64,
                    &self.genesis_key,
                    self.genesis_key.public_key(),
                    encode_peer_to_peer_with_metadata_script(
                        xus_tag(),
                        account.address,
                        init_account_balance,
                        vec![],
                        vec![],
                    ),
                );
                transactions.push(txn);
            }

            println!("SEND MINT BLOCK");
            self.block_sender
                .as_ref()
                .unwrap()
                .send(transactions)
                .unwrap();
        }
    }

    /// Generates transactions for random pairs of accounts.
    fn gen_transfer_transactions(&mut self, block_size: usize, num_blocks: usize) {
        println!("NUM BLOCKS: {}", num_blocks);
        for _i in 0..num_blocks {
            let mut transactions = Vec::with_capacity(block_size);
            for _j in 0..block_size {
                let indices = rand::seq::index::sample(&mut self.rng, self.accounts.len(), 2);
                let sender_idx = indices.index(0);
                let receiver_idx = indices.index(1);

                let sender = &self.accounts[sender_idx];
                let receiver = &self.accounts[receiver_idx];
                let txn = create_transaction(
                    sender.address,
                    sender.sequence_number,
                    &sender.private_key,
                    sender.public_key.clone(),
                    encode_peer_to_peer_with_metadata_script(
                        xus_tag(),
                        receiver.address,
                        1, /* amount */
                        vec![],
                        vec![],
                    ),
                );
                transactions.push(txn);

                self.accounts[sender_idx].sequence_number += 1;
            }

            println!("SEND TRANSFER BLOCK");
            self.block_sender
                .as_ref()
                .unwrap()
                .send(transactions)
                .unwrap();
        }
    }

    /// Drops the sender to notify the receiving end of the channel.
    fn drop_sender(&mut self) {
        self.block_sender.take().unwrap();
    }
}

/// Runs the benchmark with given parameters.
pub fn run_benchmark(
    num_accounts: usize,
    init_account_balance: u64,
    block_size: usize,
    num_transfer_blocks: usize,
    _db_dir: Option<PathBuf>,
) {
    let (config, genesis_key) = diem_genesis_tool::test_config();
    let (block_sender, block_receiver) = mpsc::sync_channel(50 /* bound */);

    let mut state_view = DictDB::new();
    let genesis_transaction = get_genesis_txn(&config).unwrap();
    let result = DiemVM::execute_block(vec![genesis_transaction.clone()], &state_view)
        .map_err(anyhow::Error::from)
        .unwrap();
    state_view.update(result);

    // Spawn two threads to run transaction generator and executor separately.
    let gen_thread = std::thread::Builder::new()
        .name("txn_generator".to_string())
        .spawn(move || {
            let mut generator = TransactionGenerator::new(genesis_key, num_accounts, block_sender);
            generator.run(init_account_balance, block_size, num_transfer_blocks);
            generator
        })
        .expect("Failed to spawn transaction generator thread.");

    let exe_thread = std::thread::Builder::new()
        .name("txn_executor".to_string())
        .spawn(move || {
            while let Ok(transactions) = block_receiver.recv() {
                let num_txns = transactions.len();
                let execute_start = std::time::Instant::now();
                let result = DiemVM::execute_block(transactions, &state_view)
                    .map_err(anyhow::Error::from)
                    .unwrap();
                let execute_time = std::time::Instant::now().duration_since(execute_start);

                info!(
                    "Version: XX. execute time: {} ms. commit time: XX ms. TPS: {}.",
                    execute_time.as_millis(),
                    num_txns as u128 * 1_000_000_000 / execute_time.as_nanos(),
                );

                state_view.update(result);
            }
        })
        .expect("Failed to spawn transaction executor thread.");

    // Wait for generator to finish and get back the generator.
    let mut generator = gen_thread.join().unwrap();
    // Drop the sender so the executor thread can eventually exit.
    generator.drop_sender();
    // Wait until all transactions are committed.
    exe_thread.join().unwrap();

    // Do a sanity check on the sequence number to make sure all transactions are committed.
    // generator.verify_sequence_number(db.as_ref());
}

pub struct DictDB {
    pub db: HashMap<AccessPath, Vec<u8>>,
    pub boot: bool,
}

impl DictDB {
    pub fn new() -> DictDB {
        DictDB {
            db: HashMap::new(),
            boot: true,
        }
    }

    pub fn update(&mut self, tx_output: Vec<TransactionOutput>) {
        for output in tx_output {
            for (path, action) in output.write_set() {
                match action {
                    WriteOp::Deletion => {
                        self.db.remove(path);
                    }
                    WriteOp::Value(v) => {
                        self.db.insert(path.clone(), v.clone());
                    }
                }
            }
        }
    }
}

impl StateView for DictDB {
    /// Gets the state for a single access path.
    fn get(&self, access_path: &AccessPath) -> anyhow::Result<Option<Vec<u8>>> {
        match self.db.get(access_path) {
            None => Ok(None),
            Some(x) => Ok(Some(x.clone())),
        }
    }

    /// Gets states for a list of access paths.
    fn multi_get(&self, access_paths: &[AccessPath]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let mut results = Vec::new();
        for path in access_paths {
            results.push(self.get(path).unwrap());
        }
        return Ok(results);
    }

    /// VM needs this method to know whether the current state view is for genesis state creation.
    /// Currently TransactionPayload::WriteSet is only valid for genesis state creation.
    fn is_genesis(&self) -> bool {
        self.boot
    }
}

fn create_transaction(
    sender: AccountAddress,
    sequence_number: u64,
    private_key: &Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    program: Script,
) -> Transaction {
    let now = diem_infallible::duration_since_epoch();
    let expiration_time = now.as_secs() + 3600;

    let raw_txn = RawTransaction::new_script(
        sender,
        sequence_number,
        program,
        1_000_000,           /* max_gas_amount */
        0,                   /* gas_unit_price */
        XUS_NAME.to_owned(), /* gas_currency_code */
        expiration_time,
        ChainId::test(),
    );

    let signature = private_key.sign(&raw_txn);
    let signed_txn = SignedTransaction::new(raw_txn, public_key, signature);
    Transaction::UserTransaction(signed_txn)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_benchmark() {
        super::run_benchmark(
            25,   /* num_accounts */
            10,   /* init_account_balance */
            5,    /* block_size */
            5,    /* num_transfer_blocks */
            None, /* db_dir */
        );
    }
}
