# Creator Token Standards

**A backwards compatible library of NFT contract standards and mix-ins that power programmable royalty use cases and expand possible NFT use cases by introducing creator tokens.** 

## Installation with Foundry

With an existing foundry project:

```bash
forge install OpenZeppelin/openzeppelin-contracts@v4.8.3
forge install chiru-labs/ERC721A@v4.2.3
forge install dmfxyz/murky
forge install limitbreakinc/creator-token-standards
```

Add a `remappings.txt` file to the root of your project and add the following contents to resolve imports.

```
@limitbreak/creator-token-standards/=lib/creator-token-standards/
@openzeppelin/=lib/openzeppelin-contracts/
ds-test/=lib/forge-std/lib/ds-test/src/
forge-std/=lib/forge-std/src/
murky/=lib/murky/src
erc721a/=lib/ERC721A/
```

## Installation with Hardhat

With an existing hardhat project:

```bash
npm install --save @limitbreak/creator-token-standards
```

***Note: Should be used in conjunection with openzeppelin v4.8.3***

## Usage

Once installed, you can use the contracts in the library by importing them.

***Note: This contract library contains Initializable variations of several contracts an mix-ins.  The initialization functions are meant for use ONLY with EIP-1167 Minimal Proxies (Clones).  The use of the term "Initializable" is not meant to imply that these contracts are suitable for use in Upgradeable Proxy contracts.  This contract library should NOT be used in any upgradeable contract, as they do not provide storage-safety should additional contract variables be added in future versions.  Limit Break has no intentions to make this library suitable for upgradeability and developers are solely responsible for adapting the code should they use it in an upgradeable contract.*** 

## Cloning The Source Code

```bash
git clone https://github.com/limitbreakinc/creator-token-standards.git
```

### Build

```bash
forge build
```

### Test

```bash
forge test
```

### Code Coverage

```bash
./scripts/test/generate-coverage-report.sh
```

### Documentation

```bash
forge doc -s
> Serving on: http://localhost:3000
```

Open a browser to http://localhost:3000 to view docs.

### Deploying The Registry

```bash
./script/common/0-create2-transfer-validator-v2.sh
./script/common/1-deploy-transfer-validator-v2.sh --gas-price <gas-price> --priority-gas-price <priority-gas-price> --chain-id <chain-id>
```

## Overview

* **Extended NFT Standards**
   * [AdventureERC721](./src/adventures/AdventureERC721.sol) - Limit Break's adventure token standard that provides flexible hard and soft staking mechanics to enable on-chain adventures and quests.
   * [ERC721C](./src/erc721c/ERC721C.sol) - Extends OpenZeppelin's ERC721 implementation, adding creator-definable transfer security profiles that are the foundation for enforceable, programmable royalties.
   * [ERC1155C](./src/erc1155c/ERC1155C.sol) - Extends OpenZeppelin's ERC1155 implementation, adding creator-definable transfer security profiles that are the foundation for enforceable, programmable royalties.
   * [AdventureERC721C](./src/erc721c/AdventureERC721C.sol) - Extends Limit Break's AdventureERC721 implementation, adding creator-definable transfer security profiles that are the foundation for enforceable, programmable royalties.
   * [ERC721AC](./src/erc721c/ERC721AC.sol) - Extends Azuki's ERC721-A implementation, adding creator-definable transfer security profiles that are the foundation for enforceable, programmable royalties.
   * [ERC20C](./src/erc20c/ERC20C.sol) - Extends OpenZeppelin's ERC20 implementation, adding creator-definable transfer security profiles that are the foundation for enforceable, programmable royalties.

* **Wrapper Standards**
   * [ERC721CW](./src/erc721c/extensions/ERC721CW.sol) - Extends ERC721C and introduces opt-in staking/unstaking as a form of token wrapping/unwrapping. This is backwards compatible and enables any vanilla ERC721 token to be upgraded to an ERC721C with enhanced utility at the discretion of token holders who can choose whether to stake into the new state or not.
   * [ERC1155CW](./src/erc1155c/extensions/ERC1155CW.sol) - Extends ERC1155C and introduces opt-in staking/unstaking as a form of token wrapping/unwrapping. This is backwards compatible and enables any vanilla ERC1155 token to be upgraded to an ERC1155C with enhanced utility at the discretion of token holders who can choose whether to stake into the new state or not.
   * [AdventureERC721CW](./src/erc721c/extensions/AdventureERC721CW.sol) - Extends AdventureERC721C and introduces opt-in staking/unstaking as a form of token wrapping/unwrapping. This is backwards compatible and enables any vanilla ERC721 token to be upgraded to an AdventureERC721C with enhanced utility at the discretion of token holders who can choose whether to stake into the new state or not.
   * [ERC20CW](./src/erc20c/extensions/ERC20CW.sol) - Extends ERC20C and introduces opt-in staking/unstaking as a form of token wrapping/unwrapping. This is backwards compatible and enables any vanilla ERC20 token to be upgraded to an ERC20C with enhanced utility at the discretion of token holders who can choose whether to stake into the new state or not.

* **Interfaces** - for ease of integration, the following interfaces have been defined for 3rd party consumption
    * [ICreatorToken](./src/interfaces/ICreatorToken.sol) - Base interface for all Creator Token Implementations.
    * [ICreatorTokenWrapperERC721](./src/interfaces/ICreatorTokenWrapperERC721.sol) - Base interface for all Wrapper Creator Token ERC721 Implementations.
    * [ICreatorTokenWrapperERC1155](./src/interfaces/ICreatorTokenWrapperERC1155.sol) - Base interface for all Wrapper Creator Token ERC1155 Implementations.
    * [ICreatorTokenWrapperERC20](./src/interfaces/ICreatorTokenWrapperERC20.sol) - Base interface for all Wrapper Creator Token ERC20 Implementations.
    * [IEOARegistry](./src/interfaces/IEOARegistry.sol) - Base interface for an EOA Registry.
    * [ITransferValidator](./src/interfaces/ITransferValidator.sol) - Base interface for a transfer validator to apply transfer security to token transfers.

* **Infrastructure**
   * [EOARegistry](./src/utils/EOARegistry.sol) - A deployable contract where users can sign a message to prove they are an EOA. A global community-use EOA registry will be deployed and made available as there is no real need for users to prove they are an EOA in more than one contract.
   * [CreatorTokenTransferValidator](./src/utils/CreatorTokenTransferValidator.sol) - Enables creators to set transfer security levels, create and manage whitelists/contract receiver allow lists, and apply their creator-defined policies to one or more creator token collections they own.  All the different implementations of creator token standards point to this registry for application of transfer security policies.

* **Programmable Royalty Sample Mix-Ins for ERC-721**
    * [ImmutableMinterRoyalties](./src/programmable-royalties/ImmutableMinterRoyalties.sol) - A mix-in that grants minters permanent royalty rights to the NFT token ID they minted.  Royalty fee cannot be changed.
    * [MutableMinterRoyalties](./src/programmable-royalties/MutableMinterRoyalties.sol) - A mix-in that grants minters permanent royalty rights to the NFT token ID they minted.  Royalty fee for each token ID can be changed by the minter of that token id.
    * [MinterCreatorSharedRoyalties](./src/programmable-royalties/MinterCreatorSharedRoyalties.sol) - A mix-in that grants minters a permanent share of royalty rights to the NFT token ID they minted.  Royalty fees for each token ID are shared between the NFT creator and the minter according to a ratio of shares defined at contract creation.  A payment splitter is created for each token ID to split funds between the minter and creator.

 * **Miscellaneous**
   * [EOARegistryAccess](./src/utils/EOARegistryAccess.sol) - A mix-in that can be applied to any contract that has a need to verify an arbitrary address is a verified EOA.
   * [TransferValidation](./src/utils/TransferValidation.sol) - A mix-in that can be used to decompose _beforeTransferToken and _afterTransferToken into granular pre and post mint/burn/transfer validation hooks.  These hooks provide finer grained controls over the lifecycle of an ERC721 token.

* **Presets**
   * [ERC721CWPermanent](./src/erc721c/presets/ERC721CWPermanent.sol) - does not allow unstaking to retrieve the wrapped token.
   * [ERC721CWPaidUnstake](./src/erc721c/presets/ERC721CWPaidUnstake.sol) - allows unstaking with payment of an unstaking fee.
   * [ERC721CWTimeLockedUnstake](./src/erc721c/presets/ERC721CWTimeLocked.sol) -  allows unstaking any time after a time lock expires.
   * [ERC1155CWPermanent](./src/erc1155c/presets/ERC1155CWPermanent.sol) - does not allow unstaking to retrieve the wrapped token.
   * [ERC1155CWPaidUnstake](./src/erc1155c/presets/ERC1155CWPaidUnstake.sol) - allows unstaking with payment of an unstaking fee.
   * [ERC20CWPermanent](./src/erc20c/presets/ERC20CWPermanent.sol) - does not allow unstaking to retrieve the wrapped token.
   * [ERC20CWPaidUnstake](./src/erc20c/presets/ERC20CWPaidUnstake.sol) - allows unstaking with payment of an unstaking fee.

* **Examples**
   * [ERC721CWithImmutableMinterRoyalties](./src/examples/erc721c/ERC721CWithImmutableMinterRoyalties.sol)
   * [ERC721CWithMutableMinterRoyalties](./src/examples/erc721c/ERC721CWithMutableMinterRoyalties.sol)
   * [ERC721CWithMinterCreatorSharedRoyalties](./src/examples/erc721c/ERC721CWithMinterCreatorSharedRoyalties.sol)
   * [ERC721ACWithImmutableMinterRoyalties](./src/examples/erc721ac/ERC721ACWithImmutableMinterRoyalties.sol)
   * [ERC721ACWithMutableMinterRoyalties](./src/examples/erc721ac/ERC721ACWithMutableMinterRoyalties.sol)
   * [ERC721ACWithMinterCreatorSharedRoyalties](./src/examples/erc721ac/ERC721ACWithMinterCreatorSharedRoyalties.sol)
   * [AdventureERC721CWithImmutableMinterRoyalties](./src/examples/adventure-erc721c/AdventureERC721CWithImmutableMinterRoyalties.sol)
   * [AdventureERC721CWithMutableMinterRoyalties](./src/examples/adventure-erc721c/AdventureERC721CWithMutableMinterRoyalties.sol)
   * [AdventureERC721CWithMinterCreatorSharedRoyalties](./src/examples/adventure-erc721c/AdventureERC721CWithMinterCreatorSharedRoyalties.sol)

## How To Guides

### How To Build, Deploy, and Setup a Creator Token

1. Choose a standard (ERC721-C, ERC721-AC, AdventureERC721-C, ERC1155-C, or ERC20-C)
2. Inherit the selected standard and desired mix-ins.  The following example is a basic ERC721-C with an open mint and basic royalties.

```solidity
pragma solidity ^0.8.4;

import "@limitbreak/creator-token-standards/src/access/OwnableBasic.sol";
import "@limitbreak/creator-token-standards/src/erc721c/ERC721C.sol";
import "@limitbreak/creator-token-standards/src/programmable-royalties/BasicRoyalties.sol";

contract ERC721CWithBasicRoyalties is OwnableBasic, ERC721C, BasicRoyalties {

    constructor(
        address royaltyReceiver_,
        uint96 royaltyFeeNumerator_,
        string memory name_,
        string memory symbol_) 
        ERC721OpenZeppelin(name_, symbol_) 
        BasicRoyalties(royaltyReceiver_, royaltyFeeNumerator_) {
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721C, ERC2981) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }

    function safeMint(address to, uint256 tokenId) external {
        _safeMint(to, tokenId);
    }

    function burn(uint256 tokenId) external {
        _burn(tokenId);
    }

    function setDefaultRoyalty(address receiver, uint96 feeNumerator) public {
        _requireCallerIsContractOwner();
        _setDefaultRoyalty(receiver, feeNumerator);
    }

    function setTokenRoyalty(uint256 tokenId, address receiver, uint96 feeNumerator) public {
        _requireCallerIsContractOwner();
        _setTokenRoyalty(tokenId, receiver, feeNumerator);
    }
}

```

4. Deploy and verify contract.  It is assumed developers already know how to do this, but instructions for [Foundry can be found here.](https://book.getfoundry.sh/forge/deploying)

5. It is strongly encouraged to transfer ownership of your contracts to a multi-sig, such as Gnosis Safe and to require multiple keys to sign off on each transaction.

6. To configure collection security and trading settings, use [developers.freenft.com](https://developers.freenft.com).

### How To Use The Creator Token Transfer Validator To Manage Security Settings For Collections

The `CreatorTokenTransferValidator` is a smart contract used for managing and applying security policies to token transfers. It provides a comprehensive set of configurable security policies to help control token transfers, while also allowing external on-chain whitelisting and blacklisting of accounts and codehashes.  The magic of creator tokens is applied in this infrastructure contract.  Limit Break has deployed this contract on Ethereum Mainnet, Polygon Mainnet, as well as Sepolia and Mumbai testnets at the following addresses: 

- Version 1: `0x0000721C310194CcfC01E523fc93C9cCcFa2A0Ac`
- Version 2: `0x721C00182a990771244d7A71B9FA2ea789A3b433`
- Version 3: `0x721C0078c2328597Ca70F5451ffF5A7B38D4E947`
- Version 4: `0x721C002B0059009a671D00aD1700c9748146cd1B`

The `CreatorTokenTransferValidator` V3 has the following features:

- Create, manage, and apply security policies for token transfers
- Enable authorization mode and add accounts to a list of allowed authorizers to transfer tokens without applying the security policy
- Manage whitelists/blacklists
- Apply different security policies to different collections
- Control token transfers based on the caller and receiver constraints
- Enable account freezing and add accounts to a list of frozen accounts to prevent transfers to or from those accounts
- Use events to track changes in security policies and allowlists

The `Creator Token Transfer Validator` V4 release has the same features as V3 with the ability to permissionlessly deploy to any EVM blockchain. To deploy the V4 validator, use [developers.freenft.com/infrastructure](https://developers.erc721c.com/infrastructure).

Interact with the deployed contract using the provided functions to create, manage, and apply security policies.  A multi-sig such as Gnosis safe is strongly encouraged, and the Gnosis Safe transaction builder can be used to securely manage collections using the following functions.

#### Security Policy Management
- `validateTransfer(address caller, address from, address to):` Validates a token transfer based on the security policy applied to the collection.
- `validateTransfer(address caller, address from, address to, uint256 tokenId):` Validates a token transfer based on the security policy applied to the collection for a specific token id.
- `validateTransfer(address caller, address from, address to, uint256 tokenId, uint256 amount):` Validates a token transfer based on the security policy applied to the collection for a specific token id and amount.
- `applyCollectionTransferPolicy(address caller, address from, address to):` Validates a token transfer based on the security policy applied to the collection.
- `setTransferSecurityLevelOfCollection(address collection, uint8 level, bool enableAuthorizationMode, bool authorizersCanSetWildcardOperators, bool enableAccountFreezingMode):` Sets the security level of a collection.
- `getCollectionSecurityPolicy(address collection) external view returns (CollectionSecurityPolicyV3 memory):` Gets the security policy for a collection.
- `beforeAuthorizedTransfer(address operator, address token, uint256 tokenId):` Activates authorization mode for an operator to transfer a token without applying the transfer constraints for a specific collection and token id.
- `afterAuthorizedTransfer(address token, uint256 tokenId):` Deactivates authorization mode for the specific collection and token id.
- `beforeAuthorizedTransfer(address operator, address token):` Activates authorization mode for an operator to transfer tokens in a collection without applying the transfer constraints.
- `afterAuthorizedTransfer(address token):` Deactivates authorization mode for the collection.
- `beforeAuthorizedTransfer(address token, uint256 tokenId):` Activates authorization mode for any operator to transfer a token without applying the transfer constraints for a specific collection and token id.
- `beforeAuthorizedTransferWithAmount(address token, uint256 tokenId, uint256 amount):` Activates authorization mode for an operator to transfer a token without applying the transfer constraints for a specific collection and token id up to a specific amount.
- `afterAuthorizedTransferWithAmount(address token, uint256 tokenId):` Deactivates authorization mode for the specific collection and token id when an amount was previously authorized.

#### List Management
- `function applyListToCollection(address collection, uint120 id) external;`
- `function createList(string calldata name) external returns (uint120);`
- `function createListCopy(string calldata name, uint120 sourceListId) external returns (uint120);`
- `function reassignOwnershipOfList(uint120 id, address newOwner) external;`
- `function renounceOwnershipOfList(uint120 id) external;`
- `function addAccountsToBlacklist(uint120 id, address[] calldata accounts) external;`
- `function addAccountsToWhitelist(uint120 id, address[] calldata accounts) external;`
- `function addCodeHashesToBlacklist(uint120 id, bytes32[] calldata codehashes) external;`
- `function addCodeHashesToWhitelist(uint120 id, bytes32[] calldata codehashes) external;`
- `function removeAccountsFromBlacklist(uint120 id, address[] calldata accounts) external;`
- `function removeAccountsFromWhitelist(uint120 id, address[] calldata accounts) external;`
- `function removeCodeHashesFromBlacklist(uint120 id, bytes32[] calldata codehashes) external;`
- `function removeCodeHashesFromWhitelist(uint120 id, bytes32[] calldata codehashes) external;`
- `function getBlacklistedAccounts(uint120 id) external view returns (address[] memory);`
- `function getWhitelistedAccounts(uint120 id) external view returns (address[] memory);`
- `function getBlacklistedCodeHashes(uint120 id) external view returns (bytes32[] memory);`
- `function getWhitelistedCodeHashes(uint120 id) external view returns (bytes32[] memory);`
- `function isAccountBlacklisted(uint120 id, address account) external view returns (bool);`
- `function isAccountWhitelisted(uint120 id, address account) external view returns (bool);`
- `function isCodeHashBlacklisted(uint120 id, bytes32 codehash) external view returns (bool);`
- `function isCodeHashWhitelisted(uint120 id, bytes32 codehash) external view returns (bool);`
- `function getBlacklistedAccountsByCollection(address collection) external view returns (address[] memory);`
- `function getWhitelistedAccountsByCollection(address collection) external view returns (address[] memory);`
- `function getBlacklistedCodeHashesByCollection(address collection) external view returns (bytes32[] memory);`
- `function getWhitelistedCodeHashesByCollection(address collection) external view returns (bytes32[] memory);`
- `function isAccountBlacklistedByCollection(address collection, address account) external view returns (bool);`
- `function isAccountWhitelistedByCollection(address collection, address account) external view returns (bool);`
- `function isCodeHashBlacklistedByCollection(address collection, bytes32 codehash) external view returns (bool);`
- `function isCodeHashWhitelistedByCollection(address collection, bytes32 codehash) external view returns (bool);`
- `function addAccountsToAuthorizers(uint120 id, address[] calldata accounts) external;`
- `function removeAccountsFromAuthorizers(uint120 id, address[] calldata accounts) external;`
- `function getAuthorizerAccounts(uint120 id) public view returns (address[] memory);`
- `function isAccountAuthorizer(uint120 id, address account) public view returns (bool);`
- `function getAuthorizerAccountsByCollection(address collection) external view returns (address[] memory);`
- `function isAccountAuthorizerOfCollection(address collection, address account) external view returns (bool);`
- `function freezeAccountsForCollection(address collection, address[] calldata accountsToFreeze) external;`
- `function unfreezeAccountsForCollection(address collection, address[] calldata accountsToUnfreeze) external;`
- `function getFrozenAccountsByCollection(address collection) external view returns (address[] memory);`
- `function isAccountFrozenForCollection(address collection, address account) external view returns (bool);`


#### Events
- `event CreatedList(uint256 indexed id, string name);`
- `event AppliedListToCollection(address indexed collection, uint120 indexed id);`
- `event ReassignedListOwnership(uint256 indexed id, address indexed newOwner);`
- `event AddedAccountToList(ListTypes indexed kind, uint256 indexed id, address indexed account);`
- `event AddedCodeHashToList(ListTypes indexed kind, uint256 indexed id, bytes32 indexed codehash);`
- `event RemovedAccountFromList(ListTypes indexed kind, uint256 indexed id, address indexed account);`
- `event RemovedCodeHashFromList(ListTypes indexed kind, uint256 indexed id, bytes32 indexed codehash);`
- `event SetTransferSecurityLevel(address indexed collection, TransferSecurityLevels level);`

For more information, please refer to the contract code comments and the provided function descriptions.

The `CreatorTokenTransferValidator` contract defines 9 transfer security levels, each represented by a unique `Transfer Security Policy`. Each policy consists of a combination of caller and receiver constraints to define varying levels of security for token transfers.

#### **Transfer Security Levels Description (V3)**

0. **Transfer Security Level - Recommended:**

   - Caller Constraints: OperatorWhitelistEnableOTC (Over-the-counter)
   - Receiver Constraints: None
   - In this level, the caller must be whitelisted as an operator or the owner of the token. There are no constraints on the receiver. (Default Equivalent To Level Three)

1. **Transfer Security Level - One**

   - Caller Constraints: None
   - Receiver Constraints: None
   - This is the most relaxed level of security, allowing any caller to initiate a token transfer to any receiver without any restrictions.

2. **Transfer Security Level - Two**

   - Caller Constraints: OperatorBlacklistEnableOTC (Over-the-counter)
   - Receiver Constraints: None
   - In this level, the caller must not be a blacklisted account or have a blacklisted code hash. There are no constraints on the receiver.

3. **Transfer Security Level - Three**

   - Caller Constraints: OperatorWhitelistEnableOTC (Over-the-counter)
   - Receiver Constraints: None
   - In this level, the caller must be whitelisted, or the owner of the token. There are no constraints on the receiver.

4. **Transfer Security Level - Four**

   - Caller Constraints: OperatorWhitelistDisableOTC
   - Receiver Constraints: None
   - The caller or owner must be whitelisted, and OTC transfers initiated by the token owner are not allowed, unless the token owner is a whitelisted account or has a whitelisted code hash. There are no constraints on the receiver.

5. **Transfer Security Level - Five**

   - Caller Constraints: OperatorWhitelistEnableOTC
   - Receiver Constraints: NoCode
   - The caller must be whitelisted, or the owner of the token. The receiver must not have deployed code, which means they cannot be a smart contract.  If the receiver does have code, the receiver may receive the token only if the account or code hash is whitelisted.

6. **Transfer Security Level - Six**

   - Caller Constraints: OperatorWhitelistEnableOTC
   - Receiver Constraints: EOA (Externally Owned Account)
   - The caller must be whitelisted, or the owner of the token. The receiver must be an EOA, which means they cannot be a smart contract and must have performed a one-time signature verification in the `CreatorTokenTransferValidator`.  If the receiver is not a proven EOA, the receiver may receive the token only if the account or code hash is whitelisted.

7. **Transfer Security Level - Seven**

   - Caller Constraints: OperatorWhitelistDisableOTC
   - Receiver Constraints: NoCode
   - The caller must be whitelisted, and OTC transfers initiated by the token owner are not allowed, unless the token owner is a whitelisted account or has a whitelisted code hash. The receiver must not have deployed code, which means they cannot be a smart contract.  If the receiver does have code, the receiver may receive the token only if the account or code hash is whitelisted.

8. **Transfer Security Level - Eight**

   - Caller Constraints: OperatorWhitelistDisableOTC
   - Receiver Constraints: EOA
   - The caller must be whitelisted, and OTC transfers initiated by the token owner are not allowed, unless the token owner is a whitelisted account or has a whitelisted code hash. The receiver must be an EOA, which means they cannot be a smart contract and must have performed a one-time signature verification in the `CreatorTokenTransferValidator`.  If the receiver is not a proven EOA, the receiver may receive the token only if the account or code hash is whitelisted.

6. **Transfer Security Level - Nine**

   - Caller Constraints: Soulbound Token, No Transfers Allowed
   - Receiver Constraints: Soulbound Token, No Transfers Allowed
   - Security level nine is a soulbound token that blocks all transfers.


These predefined transfer security levels can be applied to collections to implement varying levels of transfer security based on the collection's requirements.

### Disclaimer
It is crucial to thoroughly test the integration of this mixin with your specific marketplace implementation to ensure the security and proper functioning of your platform. This mixin provides a general-purpose solution but may require adjustments or customizations depending on your use case.

## Limit Break Curated Whitelist / Blacklist

Limit Break curates the default whitelist that is applied unless a creator opts into a custom whitelist/blacklist.  To be considered for the whitelist or to propose a new exchange, teams can reach out to blockchain@limitbreak.com.

## Security and License

This project is made available by Limit Break in an effort to provide an open-source functional library of smart contract components to be used by other parties as precedent for individual user’s creation and deployment of smart contracts in the Etherium ecosystem (the “Limit Break Contracts”). Limit Break is committed to following, and has sought to apply, commercially reasonable best practices as it pertains to safety and security in making the Limit Break Contracts publicly available for use as precedent. Nevertheless, smart contracts are a new and emerging technology and carry a high level of technical risk and uncertainty. Despite Limit Break’s commitment and efforts to foster safety and security in their adoption, using the precedent contracts made available by this project is not a substitute for a security audit conducted by the end user. Please report any actual or suspected security vulnerabilities to our team at [security@limitbreak.com](security@limitbreak.com).

The Limit Break Contracts are made available under the [MIT License](LICENSE), which disclaims all warranties in relation to the project and which limits the liability of those that contribute and maintain the project, including Limit Break. As set out further in Limit Break’s [Terms of Service](https://limitbreak.com/tos.html), as may be amended and revised from time to time, you acknowledge that you are solely responsible for any use of the Limit Break Contracts and you assume all risks associated with any such use. For the avoidance of doubt, such assumption of risk by the user also implies all risks associated with the legality or related implications tied to the use of smart contracts in any given jurisdiction, whether now known or yet to be determined.

Limit Break's offering of the code in Creator Token Contracts has no bearing on Limit Break's own implementations of programmable royalties.
