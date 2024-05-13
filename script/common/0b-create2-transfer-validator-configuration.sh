#!/bin/bash
if [ -f .env.common ]
then
  export $(cat .env.common | xargs) 
else
    echo "Please set your .env.common file"
    exit 1
fi

constructorArgs=$(cast abi-encode "signature(address)" $DEFAULT_OWNER_ADDRESS)
constructorArgs=${constructorArgs:2}

echo "create2 CreatorTokenTransferValidatorConfiguration START"
validatorConfigurationCode="$(forge inspect src/utils/CreatorTokenTransferValidatorConfiguration.sol:CreatorTokenTransferValidatorConfiguration bytecode)"
validatorConfigurationInitCode="$validatorConfigurationCode$constructorArgs"
cast create2 --starts-with 721C00 --case-sensitive --init-code $validatorConfigurationInitCode
echo "create2 CreatorTokenTransferValidatorConfiguration END"
echo "-------------------------------------"
echo ""