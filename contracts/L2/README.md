## 📦 Deployment

### Prerequisites

Before deploying, ensure you have the following installed:

- **Node.js** (v16 or higher)
- **Scarb** (Cairo package manager)
- **Starknet Foundry** (snforge/sncast)

### Environment Setup

Create a `.env` file in the `contracts/L2` directory:

```bash
# Starknet Configuration
STARKNET_PRIVATE_KEY=your_private_key_here
STARKNET_ACCOUNT_ADDRESS=your_account_address_here
STARKNET_RPC_URL=https://starknet-sepolia.public.blastapi.io/rpc/v0_7

# Contract Configuration
OWNER_ADDRESS=0x... # Owner of deployed contracts (defaults to deployer)
MIN_RATE=1000000000000000000    # Minimum conversion rate (1.0 with 18 decimals)
MAX_RATE=2000000000000000000    # Maximum conversion rate (2.0 with 18 decimals)

# Network (optional)
STARKNET_NETWORK=sepolia
```

### Contract Deployment Order

The deployment follows this dependency order:

1. **ProofRegistry** - No dependencies
2. **L2Oracle** - Requires owner
3. **xZBERC20** - Requires owner
4. **ZeroXBridgeL2** - Requires all above contracts + rate parameters

### Post-Deployment Setup

After successful deployment:

1. **Bridge Address**: The xZBERC20 contract's bridge address is automatically set to ZeroXBridgeL2
2. **Ownership**: All contracts are owned by the specified owner address
3. **Rate Limits**: Min/max conversion rates are configured

### Available NPM Scripts

```bash
# Deployment commands
npm run deploy:testnet    # Deploy to Sepolia testnet
npm run deploy:devnet     # Deploy to local devnet
npm run deploy            # Deploy to mainnet (with confirmation)

# Utility commands
npm run deploy:validate   # Validate deployment setup
```

### Network Configuration

#### Default RPC URLs:
- **Sepolia**: `https://starknet-sepolia.public.blastapi.io/rpc/v0_8`
- **Mainnet**: `https://starknet-mainnet.public.blastapi.io/rpc/v0_8`
- **Devnet**: `http://127.0.0.1:5050`


## Deployed Contracts

### Sepolia

- Oracle Contract: [0x1e4acab001e40d194f15927bb0e832887a219809d0be6cf308f3e41a4cfd246](https://sepolia.starkscan.co/contract/0x1e4acab001e40d194f15927bb0e832887a219809d0be6cf308f3e41a4cfd246#read-write-contract)

- Proof Registry: [0x3a5d9d2fce8a9dac6a6b5c8cade5668b19e30248611159c7788236a49ce8b9a](https://sepolia.starkscan.co/contract/0x3a5d9d2fce8a9dac6a6b5c8cade5668b19e30248611159c7788236a49ce8b9a#read-write-contract-sub-read)

- xZBERC20: [0x26cfc43ee6e47541c1de22e91382c14c2c524de52d6abdd1275e7b37cb01276](https://sepolia.starkscan.co/contract/0x26cfc43ee6e47541c1de22e91382c14c2c524de52d6abdd1275e7b37cb01276#read-write-contract)

- L2Bridge: [0x58bdc4e4f39b648c01761324247d98ea68bc9fd5e3541e732d146385e575a63](https://sepolia.starkscan.co/contract/0x58bdc4e4f39b648c01761324247d98ea68bc9fd5e3541e732d146385e575a63#read-write-contract-sub-write)
