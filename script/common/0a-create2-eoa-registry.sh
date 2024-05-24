#!/bin/bash
if [ -f .env.common ]
then
  export $(cat .env.common | xargs) 
else
    echo "Please set your .env.common file"
    exit 1
fi

echo "create2 EOARegistry START"
registryCode="$(forge inspect src/utils/EOARegistry.sol:EOARegistry bytecode)"
registryInitCode="$registryCode"
cast create2 --starts-with E0A000 --case-sensitive --init-code $registryInitCode
echo "create2 EOARegistry END"
echo "-------------------------------------"
echo ""