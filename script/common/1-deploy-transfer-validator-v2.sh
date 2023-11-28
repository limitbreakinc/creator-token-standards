#!/usr/bin/env bash

if [ -f .env.common ]
then
  export $(cat .env.common | xargs) 
else
    echo "Please set your .env.common file"
    exit 1
fi

# Initialize variables
GAS_PRICE=""
PRIORITY_GAS_PRICE=""
CHAIN_ID=""
RPC_URL=""

# Function to display usage
usage() {
    echo "Usage: $0 --gas-price <gas price> --priority-gas-price <priority gas price> --chain-id <chain id>"
    exit 1
}

# Function to set RPC URL based on chain ID
set_rpc_url() {
    case $1 in
        1) RPC_URL="https://eth.llamarpc.com" ;;
        10) RPC_URL="https://optimism.llamarpc.com" ;;
        56) RPC_URL="https://bsc.meowrpc.com" ;;
        137) RPC_URL="https://polygon.llamarpc.com" ;;
        324) RPC_URL="https://mainnet.era.zksync.io" ;;
        1101) RPC_URL="https://zkevm-rpc.com" ;;
        8453) RPC_URL="https://developer-access-mainnet.base.org" ;;
        42161) RPC_URL="https://arbitrum.llamarpc.com" ;;
        42170) RPC_URL="https://arbitrum-nova.publicnode.com" ;;
        43114) RPC_URL="https://avalanche-c-chain.publicnode.com" ;;
        59144) RPC_URL="https://rpc.linea.build" ;;
        7777777) RPC_URL="https://rpc.zora.co" ;;
        534352) RPC_URL="https://rpc.ankr.com/scroll" ;;
        5) RPC_URL="https://goerli.blockpi.network/v1/rpc/public" ;;
        999) RPC_URL="https://testnet.rpc.zora.co" ;;
        5001) RPC_URL="https://rpc.testnet.mantle.xyz" ;;
        59140) RPC_URL="https://rpc.goerli.linea.build/" ;;
        80001) RPC_URL="https://endpoints.omniatech.io/v1/matic/mumbai/public" ;;
        84531) RPC_URL="https://goerli.base.org" ;;
        534353) RPC_URL="https://alpha-rpc.scroll.io/l2" ;;
        11155111) RPC_URL="https://1rpc.io/sepolia" ;;
        2863311531) RPC_URL="https://rpc-testnet.ancient8.gg/" ;;
        13472) RPC_URL="https://rpc.testnet.immutable.com/" ;;
        *) echo "Unsupported chain id"; exit 1 ;;
    esac
}

# Process arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --gas-price) GAS_PRICE=$(($2 * 1000000000)); shift ;;
        --priority-gas-price) PRIORITY_GAS_PRICE=$(($2 * 1000000000)); shift ;;
        --chain-id) CHAIN_ID=$2; shift ;;
        *) usage ;;
    esac
    shift
done

# Check if all parameters are set
if [ -z "$GAS_PRICE" ] || [ -z "$PRIORITY_GAS_PRICE" ] || [ -z "$CHAIN_ID" ]; then
    usage
fi

# Set the RPC URL based on chain ID
set_rpc_url $CHAIN_ID

echo ""
echo "============= DEPLOYING CREATOR REGISTRY ============="

echo "Gas Price (wei): $GAS_PRICE"
echo "Priority Gas Price (wei): $PRIORITY_GAS_PRICE"
echo "Chain ID: $CHAIN_ID"
echo "RPC URL: $RPC_URL"
echo "SALT_TRANSFER_VALIDATOR_V2: $SALT_TRANSFER_VALIDATOR_V2"
echo "EXPECTED_VALIDATOR_ADDRESS_V2: $EXPECTED_VALIDATOR_ADDRESS_V2"
read -p "Do you want to proceed? (yes/no) " yn

case $yn in 
  yes ) echo ok, we will proceed;;
  no ) echo exiting...;
    exit;;
  * ) echo invalid response;
    exit 1;;
esac

forge script script/common/DeployV2.s.sol:DeployV2 \
  --gas-price $GAS_PRICE \
  --priority-gas-price $PRIORITY_GAS_PRICE \
  --rpc-url $RPC_URL \
  --optimize \
  --optimizer-runs 1000000 \
  --broadcast \
  --slow \
  --verify