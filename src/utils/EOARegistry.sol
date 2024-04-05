// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import "../interfaces/IEOARegistry.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title EOARegistry
 * @author Limit Break, Inc.
 * @notice A registry that may be used globally by any smart contract that limits contract interactions to verified EOA addresses only.
 * @dev Take care and carefully consider whether or not to use this. Restricting operations to EOA only accounts can break Defi composability, 
 * so if Defi composability is an objective, this is not a good option.  Be advised that in the future, EOA accounts might not be a thing
 * but this is yet to be determined.  See https://eips.ethereum.org/EIPS/eip-4337 for more information.
 */
contract EOARegistry is ERC165, IEOARegistry {

    /// @dev A pre-cached signed message hash used for gas-efficient signature recovery
    bytes32 immutable private signedMessageHash;

    /// @dev The plain text message to sign for signature verification
    string constant public MESSAGE_TO_SIGN = "EOA";

    /// @dev Mapping of accounts that to signature verification status
    mapping (address => bool) private eoaSignatureVerified;

    /// @dev Emitted whenever a user verifies that they are an EOA by submitting their signature.
    event VerifiedEOASignature(address indexed account);

    constructor() {
        signedMessageHash = ECDSA.toEthSignedMessageHash(bytes(MESSAGE_TO_SIGN));
    }

    /// @notice Allows a user to verify an ECDSA signature to definitively prove they are an EOA account.
    //          Any user can submit a signature for any other user.
    ///
    /// Postconditions:
    /// ---------------
    /// The verified signature mapping has been updated to `true` for the caller.
    /// 
    /// @param signature  The signature supplied as a bytes array by an EOA to verify their address is an EOA.
    function verifySignature(bytes calldata signature) external {
        address signer = ECDSA.recover(signedMessageHash, signature);
        eoaSignatureVerified[signer] = true;
        emit VerifiedEOASignature(signer);
    }

    /// @notice Allows a user to verify an ECDSA signature to definitively prove they are an EOA account.
    /// This version is passed the v, r, s components of the signature, and is slightly more gas efficient than
    /// calculating the v, r, s components on-chain.  Any user can submit a signature for any other user.
    ///
    /// Postconditions:
    /// ---------------
    /// The verified signature mapping has been updated to `true` for the caller.
    /// 
    /// @param v  The signature v component supplied by an EOA to verify their address is an EOA.
    /// @param r  The signature r component supplied by an EOA to verify their address is an EOA.
    /// @param s  The signature s component supplied by an EOA to verify their address is an EOA.
    function verifySignatureVRS(uint8 v, bytes32 r, bytes32 s) external {
        address signer = ECDSA.recover(signedMessageHash, v, r, s);
        eoaSignatureVerified[signer] = true;
        emit VerifiedEOASignature(signer);
    }

    /// @notice Returns true if the specified account has verified a signature on this registry, false otherwise.
    /// 
    /// @param account  The address to check to see if it has verified as an EOA.
    function isVerifiedEOA(address account) public view override returns (bool) {
        return eoaSignatureVerified[account];
    }

    /// @dev ERC-165 interface support
    /// 
    /// @param interfaceId  The identifier of the interface to check if this contract supports it.
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IEOARegistry).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}