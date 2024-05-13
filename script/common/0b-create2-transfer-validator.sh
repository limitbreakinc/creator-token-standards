#!/bin/bash
if [ -f .env.common ]
then
  export $(cat .env.common | xargs) 
else
    echo "Please set your .env.common file"
    exit 1
fi

constructorArgs=$(cast abi-encode "signature(address,address,string,string)" $DEFAULT_OWNER_ADDRESS $EXPECTED_EOA_REGISTRY_ADDRESS $VALIDATOR_NAME $VALIDATOR_VERSION)
constructorArgs=${constructorArgs:2}

echo "create2 CreatorTokenTransferValidator START"
validatorCode="$(forge inspect src/utils/CreatorTokenTransferValidator.sol:CreatorTokenTransferValidator bytecode)"
validatorInitCode="$validatorCode$constructorArgs"
cast create2 --starts-with 721C00 --case-sensitive --init-code $validatorInitCode
echo "create2 CreatorTokenTransferValidator END"
echo "-------------------------------------"
echo ""