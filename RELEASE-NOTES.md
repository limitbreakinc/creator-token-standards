## 3.0.0 (2024-05-24)

* Creator Token Transfer Validator (V3)
    * Inherit from Permit-C so that ERC20C/ERC721C/ERC1155C tokens can use permits while honoring creator-defined security settings.
    * Add Authorization Mode - when a transfer would fail due to a security settings, this is a fallback setting that allows an authorizer to "vouch" for a transfer.
        * Authorization Mode is used with Seaport 1.6 hooks, allowing a specialty royalty-enforcing zone for creators to vouch for the presense of the correct royalties, correct payment settings, correct min/max floor, etc.
        * Beyond seaport, Authorization mode can be used to enable new use cases such as KYC requirements.
        * Authorization mode, and authorizer addresses are configurable on/off by creators.
    * Add Transfer Security Level 9 (Soul-Bound Token) - blocks all transfers while using this security level .
    * Add Account Freezing Mode and Frozen Account Lists - some creators will opt to use this feature as recourse against a violation of their terms of service.
    * No longer inherits EOA Registry (which requires new EOA verification per validator).  EOA registry will become stand-alone and security levels that require EOA verification will query against the external registry.
* Creator Token Base
    * Cleanup un-necessary/deprecated helper functions and streamline Creator Token Base interfaces to reduce bytecode size.
    * Add transfer validation overloads that include validation by amount.  This is used in ERC20C and ERC1155C now.
* EOA Registry
    * There will now be a permanent stand-alone registry.
    * Any user can submit another user's signature on their behalf.

### Miscellaneous

* Validator targets >= 0.8.24 and Cancun to take advantage of TSTORE/TLOAD
* Cleanup - removed v1 and v2 code folders and older versions of the validator.  These can be used by using the proper V1 or V2 version of this library. 

## 2.0.0 (2023-11-15)

* Added Creator Token Transfer Validator V2
  * Updated Transfer Security Levels:
    * Recommended - Whitelist + OTC (NEW)
    * Level 1 - No Protection
    * Level 2 - Blacklist + OTC (NEW)
    * Level 3 - Whitelist + OTC (FORMERLY LEVEL 1)
    * Level 4 - Whitelist + No OTC (FORMERLY LEVEL 2)
    * Level 5 - Whitelist + OTC + No Transfers To Unwhitelisted Contracts (Code Length Check) (FORMERLY LEVEL 3)
    * Level 6 - Whitelist + OTC + No Transfers To Unwhitelisted Contracts (Verified EOA Check) (FORMERLY LEVEL 4)
    * Level 7 - Whitelist + No OTC + No Transfers To Unwhitelisted Contracts (Code Length Check) (FORMERLY LEVEL 5)
    * Level 8 - Whitelist + No OTC + No Transfers To Unwhitelisted Contracts (Verified EOA Check) (FORMERLY LEVEL 6)
  * Added Blacklisting Security Level
  * Removed Permitted Contract Receiver List
  * Improved Ease Of Protocol-Level Whitelisting and Blacklisting
    * Whitelisted Accounts Can Always Initiate OTC Transfers, Even For `No OTC` security levels
    * Whitelisted Accounts Can Always Receive Tokens, Even For Levels 4-7
    * Added Code Hash Whitelisting and Blacklisting
  * Improved Transfer Validation Gas Efficiency
* Added Creator Token Base V2
  * Uninitialized Collections Protected At `Recommended` Security Level w/Default Whitelist By Default
  * Added Switch For Creators To Auto-Approve Transfer Validator As A Default Operator (For Future Gasless Marketplace Approvals)
  * Minor Interface Updates
* Updated All ERC721-C and ERC1155-C Standards To V2
* Added ERC20-C Standard (EXPERIMENTAL)

## 1.1.2 (2023-06-15)

* Add README text to clarify this library is not compatible with Upgradeable contracts.
* Add documentation comments to clarify merkle mint mix-in usage.
* Fix pragma locked to 0.8.9

## 1.1.1 (2023-05-22)

* Refactored code to support either fully constructed or cloned contracts.
* Implemented EIP-1167 for payment splitter cloning to streamline the shared royalties mix-in.
* Testing code coverage improvements

### Upgrade Steps
* Use npm or yarn to install creator-token-contracts at v1.1.1

## 1.1.0 (2023-05-08)

* Formalized creator token standards, added sample programmable royalty mix-ins, a marketplace helper mix-in, and more!

### Upgrade Steps
* Use npm or yarn to install creator-token-contracts at v1.1.0

### Breaking Changes
* Replaced WhitelistedTransferERC721 with ERC721C
* Replaced CreatorERC721/EOAOnlyCreatorERC721 with ERC721CW
* Removed external Whitelist Registry contracts in favor of CreatorTokenTransferValidator

### New Features
* Added AdventureERC721 for community use
* Added CreatorTokenTransferValidator contract - a central contract where ERC721-C collections can configure their desired transfer security level and transfer whitelist
* Formalized creator token interfaces
* ERC721-C
* ERC721-CW (Wrapper Token For ERC721)
* ERC1155-C
* ERC1155-CW (Wrapper Token For ERC1155)
* AdventureERC721-C
* AdventureERC721-CW (Adventure-compatible ERC721-CW wrapper token)
* ERC721-AC (Azuki ERC721-A with creator token features)
* Sample programmable royalty mix-ins
* Onchain Royalty Order Fulfillment Mix-In for Marketplaces
* Numerous examples of how to use these contracts together
