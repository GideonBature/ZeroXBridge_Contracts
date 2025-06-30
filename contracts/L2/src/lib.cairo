pub mod core {
    pub mod xZBERC20;
    pub mod ZeroXBridgeL2;
    pub mod L2Oracle;
    pub mod ProofRegistry;
}

pub mod interfaces {
    pub mod IMerkleManager;
    pub mod IProofRegistry;
    pub mod IxZBErc20;
    pub mod IL2Oracle;
    pub mod IZeroXBridgeL2;
}

pub mod dao {
    pub mod Timelock;
    pub mod DAO;
}

pub mod mocks {
    pub mod MockRegistry;
    pub mod MockOracle;
    pub mod MockMerkleManager;
}

pub mod utils;
