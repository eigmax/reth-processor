#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// Client program input data types.
pub mod io;
#[macro_use]
mod utils;
pub mod custom;
pub mod error;
pub mod executor;
pub mod tracking;

mod into_primitives;
pub use into_primitives::{FromInput, IntoInput, IntoPrimitives, ValidateBlockPostExecution};

use alloy_primitives::B256;
use executor::{EthClientExecutor, DESERIALZE_INPUTS};
use io::EthClientExecutorInput;
use std::sync::Arc;

pub fn verify_block(input: &Vec<u8>) -> (B256, B256, B256) {
    println!("cycle-tracker-report-start: {}", DESERIALZE_INPUTS);
    let input = bincode::deserialize::<EthClientExecutorInput>(input).unwrap();
    println!("cycle-tracker-report-end: {}", DESERIALZE_INPUTS);

    // Execute the block.
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );
    let (header, prev_state_root) = executor.execute(input, None).expect("failed to execute client");
    let block_hash = header.hash_slow();
    (block_hash, header.state_root, prev_state_root)
}
