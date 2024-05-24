#!/usr/bin/env bash

if [ -f .env.secrets ]
then
  export $(cat .env.secrets | xargs) 
else
    echo "Please set your .env.secrets file"
    exit 1
fi

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
RESUME=""

# Function to display usage
usage() {
    echo "Usage: $0 --gas-price <gas price> --priority-gas-price <priority gas price> --chain-id <chain id>"
    exit 1
}

# Function to set RPC URL based on chain ID
set_rpc_url() {
    case $1 in
        1) RPC_URL=$RPC_URL_ETHEREUM ;;
        10) RPC_URL=$RPC_URL_OPTIMISM ;;
        56) RPC_URL=$RPC_URL_BSC ;;
        137) RPC_URL=$RPC_URL_POLYGON ;;
        324) RPC_URL=$RPC_URL_ZKEVM ;;
        1101) RPC_URL=$RPC_URL_POLYGON_ZKEVM ;;
        8453) RPC_URL=$RPC_URL_BASE ;;
        42161) RPC_URL=$RPC_URL_ARBITRUM ;;
        42170) RPC_URL=$RPC_URL_ARBITRUM_NOVA ;;
        43114) RPC_URL=$RPC_URL_AVALANCHE_C ;;
        59144) RPC_URL=$RPC_URL_LINEA ;;
        7777777) RPC_URL=$RPC_URL_ZORA ;;
        534352) RPC_URL=$RPC_URL_SCROLL ;;
        5) RPC_URL=$RPC_URL_GOERLI ;;
        999) RPC_URL=$RPC_URL_ZORA_TESTNET ;;
        5001) RPC_URL=$RPC_URL_MANTLE_TESTNET ;;
        59140) RPC_URL=$RPC_URL_GOERLI_LINEA ;;
        80001) RPC_URL=$RPC_URL_MUMBAI ;;
        84531) RPC_URL=$RPC_URL_GOERLI_BASE ;;
        534353) RPC_URL=$RPC_URL_SCROLL_ALPHA ;;
        11155111) RPC_URL=$RPC_URL_SEPOLIA ;;
        2863311531) RPC_URL=$RPC_URL_ANCIENT8 ;;
        13472) RPC_URL=$RPC_URL_IMMUTABLE_TESTNET ;;
        11155420) RPC_URL=$RPC_URL_SEPOLIA_OPTIMISM ;;
        84532) RPC_URL=$RPC_URL_SEPOLIA_BASE ;;
        421614) RPC_URL=$RPC_URL_SEPOLIA_ARBITRUM ;;
        80002) RPC_URL=$RPC_URL_AMOY_POLYGON ;;
        97) RPC_URL=$RPC_URL_BSC_TESTNET ;;
        43113) RPC_URL=$RPC_URL_FUJI_AVALANCHE ;;
        *) echo "Unsupported chain id"; exit 1 ;;
    esac

    export RPC_URL
}

# Function to set verification api key based on chain ID
set_etherscan_api_key() {
  case $1 in
      1) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_ETHEREUM ;;
      10) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_OPTIMISM ;;
      56) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_BSC ;;
      137) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_POLYGON ;;
      324) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_ETHEREUM ;;
      1101) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_POLYGON_ZKEVM ;;
      8453) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_BASE ;;
      42161) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_ARBITRUM ;;
      42170) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_ARBITRUM_NOVA ;;
      43114) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_ETHEREUM;; #Avalanche C-Chain
      59144) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_LINEA ;;
      7777777) echo "Unsupported chain id"; exit 1 ;; #Zora
      534352) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_SCROLL ;;
      5) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_ETHEREUM ;;
      999) echo "Unsupported chain id"; exit 1 ;; #Zora Testnet
      5001) echo "Unsupported chain id"; exit 1 ;; #Mantle Testnet
      59140) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_LINEA ;;
      80001) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_POLYGON ;; 
      84531) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_BASE ;;
      534353) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_SCROLL ;; # Scroll Alpha
      11155111) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_ETHEREUM ;;
      2863311531) echo "Unsupported chain id"; exit 1 ;; # Ancient 8 Testnet
      13472) echo "Unsupported chain id"; exit 1 ;; # Immutable X Testnet
      11155420) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_OPTIMISM ;;
      84532) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_BASE ;;
      421614) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_ARBITRUM ;;
      80002) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_POLYGON ;;
      97) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_BSC ;;
      43113) ETHERSCAN_API_KEY=$VERIFICATION_API_KEY_ETHEREUM ;; #Avalanche C-Chain
      *) echo "Unsupported chain id"; exit 1 ;;
  esac

  export ETHERSCAN_API_KEY
}

# Process arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --gas-price) GAS_PRICE=$(($2 * 1000000000)); shift ;;
        --priority-gas-price) PRIORITY_GAS_PRICE=$(($2 * 1000000000)); shift ;;
        --chain-id) CHAIN_ID=$2; shift ;;
        --resume) RESUME="--resume" ;;
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

# Set the ETHERSCAN API KEY based on chain ID
set_etherscan_api_key $CHAIN_ID

echo ""
echo "============= DEPLOYING CREATOR VALIDATOR CONFIGURATION ============="

echo "Gas Price (wei): $GAS_PRICE"
echo "Priority Gas Price (wei): $PRIORITY_GAS_PRICE"
echo "Chain ID: $CHAIN_ID"
echo "RPC URL: $RPC_URL"
echo "SALT_TRANSFER_VALIDATOR_CONFIGURATION: $SALT_TRANSFER_VALIDATOR_CONFIGURATION"
echo "EXPECTED_VALIDATOR_CONFIGURATION_ADDRESS: $EXPECTED_VALIDATOR_CONFIGURATION_ADDRESS"
echo "DEFAULT_OWNER_ADDRESS: $DEFAULT_OWNER_ADDRESS"
read -p "Do you want to proceed? (yes/no) " yn

case $yn in 
  yes ) echo ok, we will proceed;;
  no ) echo exiting...;
    exit;;
  * ) echo invalid response;
    exit 1;;
esac

forge script script/common/DeployValidatorConfiguration.s.sol:DeployValidatorConfiguration \
  --gas-price $GAS_PRICE \
  --priority-gas-price $PRIORITY_GAS_PRICE \
  --rpc-url $RPC_URL \
  --broadcast \
  --optimizer-runs 777 \
  --verify $RESUME