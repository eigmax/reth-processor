use std::{marker::PhantomData, sync::RwLock};

use alloy_evm::EthEvmFactory;
use alloy_network::Ethereum;
use alloy_provider::Network;
use eyre::eyre;
use guest_executor::{
    custom::CustomEvmFactory, IntoInput, IntoPrimitives, ValidateBlockPostExecution,
};
use lazy_static::lazy_static;
use op_alloy_network::Optimism;
use reth_ethereum_primitives::EthPrimitives;
use reth_evm::ConfigureEvm;
use reth_evm_ethereum::EthEvmConfig;
use reth_optimism_evm::OpEvmConfig;
use reth_optimism_primitives::OpPrimitives;
use reth_primitives_traits::NodePrimitives;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use zkm_prover::{components::DefaultProverComponents, ZKMProvingKey};
use zkm_sdk::{
    NetworkProver, Prover, ProverClient, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin,
};

use crate::ExecutionHooks;

lazy_static! {
    static ref ELF_ID: RwLock<String> = RwLock::new(Default::default());
}

pub trait ExecutorComponents {
    type Prover: Prover<DefaultProverComponents> + MaybeProveWithCycles + 'static;

    type Network: Network;

    type Primitives: NodePrimitives
        + DeserializeOwned
        + IntoPrimitives<Self::Network>
        + IntoInput
        + ValidateBlockPostExecution;

    type EvmConfig: ConfigureEvm<Primitives = Self::Primitives>;

    type Hooks: ExecutionHooks;
}

#[derive(Debug, Default)]
pub struct EthExecutorComponents<H, P = ProverClient> {
    phantom: PhantomData<(H, P)>,
}

impl<H, P> ExecutorComponents for EthExecutorComponents<H, P>
where
    H: ExecutionHooks,
    P: Prover<DefaultProverComponents> + MaybeProveWithCycles + 'static,
{
    type Prover = P;

    type Network = Ethereum;

    type Primitives = EthPrimitives;

    type EvmConfig = EthEvmConfig<CustomEvmFactory<EthEvmFactory>>;

    type Hooks = H;
}

#[derive(Debug, Default)]
pub struct OpExecutorComponents<H, P = ProverClient> {
    phantom: PhantomData<(H, P)>,
}

impl<H, P> ExecutorComponents for OpExecutorComponents<H, P>
where
    H: ExecutionHooks,
    P: Prover<DefaultProverComponents> + MaybeProveWithCycles + 'static,
{
    type Prover = P;

    type Network = Optimism;

    type Primitives = OpPrimitives;

    type EvmConfig = OpEvmConfig;

    type Hooks = H;
}

pub trait MaybeProveWithCycles {
    fn prove_with_cycles(
        &self,
        pk: &ZKMProvingKey,
        stdin: &ZKMStdin,
        mode: ZKMProofKind,
    ) -> impl std::future::Future<
        Output = Result<(ZKMProofWithPublicValues, Option<u64>), eyre::Error>,
    > + Send;
}

impl MaybeProveWithCycles for ProverClient {
    async fn prove_with_cycles(
        &self,
        pk: &ZKMProvingKey,
        stdin: &ZKMStdin,
        mode: ZKMProofKind,
    ) -> Result<(ZKMProofWithPublicValues, Option<u64>), eyre::Error> {
        let mut prove = self.prove(pk, stdin.clone());
        prove = match mode {
            ZKMProofKind::Core => prove.core(),
            ZKMProofKind::Compressed => prove.compressed(),
            ZKMProofKind::Groth16 => prove.groth16(),
            ZKMProofKind::Plonk => prove.plonk(),
            ZKMProofKind::CompressToGroth16 => unreachable!(),
        };
        let proof = prove.run().map_err(|err| eyre!("{err}"))?;

        Ok((proof, None))
    }
}

impl MaybeProveWithCycles for NetworkProver {
    async fn prove_with_cycles(
        &self,
        pk: &ZKMProvingKey,
        stdin: &ZKMStdin,
        mode: ZKMProofKind,
    ) -> Result<(ZKMProofWithPublicValues, Option<u64>), eyre::Error> {
        debug_assert!(
            mode == ZKMProofKind::Compressed || mode == ZKMProofKind::Groth16,
            "NetworkProver only supports Compressed and Groth16 proof modes"
        );

        let elf_id = hex::encode(Sha256::digest(&pk.elf));

        let (elf, elf_id) = if *ELF_ID.read().unwrap() != elf_id {
            let mut id = ELF_ID.write().unwrap();
            *id = elf_id;

            (&pk.elf, None)
        } else {
            (&Default::default(), Some(elf_id))
        };
        tracing::info!("elf id: {:?}", elf_id);

        let (proof, cycles) = self
            .prove_with_cycles(elf, stdin.clone(), mode, elf_id, None)
            .await
            .map_err(|err| eyre!("Proof failed: {err}"))?;

        return Ok((proof, Some(cycles)));
    }
}
