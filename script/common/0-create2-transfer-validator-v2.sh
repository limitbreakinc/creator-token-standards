#!/bin/bash
if [ -f .env.common ]
then
  export $(cat .env.common | xargs) 
else
    echo "Please set your .env.common file"
    exit 1
fi

ownerAddress=$(cast abi-encode "signature(address)" $DEFAULT_OWNER_ADDRESS)
ownerAddress=${ownerAddress:2}

echo "create2 CreatorTokenTransferValidatorV2 START"
validatorCode="$(forge inspect src/utils/CreatorTokenTransferValidatorV2.sol:CreatorTokenTransferValidatorV2 bytecode)"
validatorInitCode="$validatorCode$ownerAddress"
cast create2 --starts-with 721C00 --case-sensitive --init-code $validatorInitCode
echo "create2 CreatorTokenTransferValidatorV2 END"
echo "-------------------------------------"
echo ""