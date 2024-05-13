// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "../ERC20C.sol";
import "../../interfaces/ICreatorTokenWrapperERC20.sol";
import "../../interfaces/IEOARegistry.sol";
import "../../utils/WithdrawETH.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title ERC20WrapperBase
 * @author Limit Break, Inc.
 * @notice Base functionality to extend ERC20-C contracts and add a staking feature used to wrap another ERC20 contract.
 * The wrapper token gives the developer access to the same set of controls present in the ERC20-C standard.  
 * Holders opt-in to this contract by staking, and it is possible for holders to unstake at the developers' discretion. 
 * The intent of this contract is to allow developers to upgrade existing NFT collections and provide enhanced features.
 * The base contract is intended to be inherited by either a constructable or initializable contract.
 *
 * @notice Creators also have discretion to set optional staker constraints should they wish to restrict staking to 
 *         EOA accounts only.
 */
abstract contract ERC20WrapperBase is WithdrawETH, ReentrancyGuard, ICreatorTokenWrapperERC20 {
    error ERC20WrapperBase__AmountMustBeGreaterThanZero();
    error ERC20WrapperBase__CallerSignatureNotVerifiedInEOARegistry();
    error ERC20WrapperBase__InsufficientBalanceOfWrappedToken();
    error ERC20WrapperBase__InsufficientBalanceOfWrappingToken();
    error ERC20WrapperBase__DefaultImplementationOfStakeDoesNotAcceptPayment();
    error ERC20WrapperBase__DefaultImplementationOfUnstakeDoesNotAcceptPayment();
    error ERC20WrapperBase__InvalidERC20Collection();
    error ERC20WrapperBase__SmartContractsNotPermittedToStake();

    /// @dev The staking constraints that will be used to determine if an address is eligible to stake tokens.
    StakerConstraints private stakerConstraints;

    /// @notice Allows the contract owner to update the staker constraints.
    ///
    /// @dev    Throws when caller is not the contract owner.
    ///
    /// Postconditions:
    /// ---------------
    /// The staker constraints have been updated.
    /// A `StakerConstraintsSet` event has been emitted.
    function setStakerConstraints(StakerConstraints stakerConstraints_) public {
        _requireCallerIsContractOwner();
        stakerConstraints = stakerConstraints_;
        emit StakerConstraintsSet(stakerConstraints_);
    }

    /// @notice Allows holders of the wrapped ERC20 token to stake into this enhanced ERC20 token.
    /// The out of the box enhancement is ERC20-C standard, but developers can extend the functionality of this 
    /// contract with additional powered up features.
    ///
    /// Throws when staker constraints is `CallerIsTxOrigin` and the caller is not the tx.origin.
    /// Throws when staker constraints is `EOA` and the caller has not verified their signature in the transfer
    /// validator contract.
    /// Throws when amount is zero.
    /// Throws when caller does not have a balance greater than or equal to `amount` of the wrapped collection.
    /// Throws when inheriting contract reverts in the _onStake function (for example, in a pay to stake scenario).
    /// Throws when _mint function reverts (for example, when additional mint validation logic reverts).
    /// Throws when safeTransferFrom function reverts (e.g. if this contract does not have approval to transfer token).
    /// 
    /// Postconditions:
    /// ---------------
    /// The specified amount of the staker's token are now owned by this contract.
    /// The staker has received the equivalent amount of wrapper token on this contract with the same id.
    /// A `Staked` event has been emitted.
    function stake(uint256 amount) public virtual payable override nonReentrant {
        StakerConstraints stakerConstraints_ = stakerConstraints;

        if (stakerConstraints_ == StakerConstraints.CallerIsTxOrigin) {
            if(_msgSender() != tx.origin) {
                revert ERC20WrapperBase__SmartContractsNotPermittedToStake();
            }
        } else if (stakerConstraints_ == StakerConstraints.EOA) {
            _requireAccountIsVerifiedEOA(_msgSender());
        }

        if (amount == 0) {
            revert ERC20WrapperBase__AmountMustBeGreaterThanZero();
        }

        IERC20 wrappedCollection_ = IERC20(getWrappedCollectionAddress());

        uint256 tokenBalance = wrappedCollection_.balanceOf(_msgSender());
        if (tokenBalance < amount) {
            revert ERC20WrapperBase__InsufficientBalanceOfWrappedToken();
        }
        
        _onStake(amount, msg.value);
        emit Staked(_msgSender(), amount);
        SafeERC20.safeTransferFrom(wrappedCollection_, _msgSender(), address(this), amount);
        _doTokenMint(_msgSender(), amount);
    }

    /// @notice Allows holders of the wrapped ERC20 token to stake into this enhanced ERC20 token.
    /// The out of the box enhancement is ERC20-C standard, but developers can extend the functionality of this 
    /// contract with additional powered up features.  This function allows a contract to stake on behalf of a user.
    ///
    /// Throws when staker constraints is `CallerIsTxOrigin` and the `to` address is not the tx.origin.
    /// Throws when staker constraints is `EOA` and the `to` address has not verified their signature in the transfer
    /// validator contract.
    /// Throws when amount is zero.
    /// Throws when caller does not have a balance greater than or equal to `amount` of the wrapped collection.
    /// Throws when inheriting contract reverts in the _onStake function (for example, in a pay to stake scenario).
    /// Throws when _mint function reverts (for example, when additional mint validation logic reverts).
    /// Throws when safeTransferFrom function reverts (e.g. if this contract does not have approval to transfer token).
    /// 
    /// Postconditions:
    /// ---------------
    /// The specified amount of the staker's token are now owned by this contract.
    /// The `to` address has received the equivalent amount of wrapper token on this contract with the same id.
    /// A `Staked` event has been emitted.
    function stakeTo(uint256 amount, address to) public virtual payable override nonReentrant {
        StakerConstraints stakerConstraints_ = stakerConstraints;

        if (stakerConstraints_ == StakerConstraints.CallerIsTxOrigin) {
            if(to != tx.origin) {
                revert ERC20WrapperBase__SmartContractsNotPermittedToStake();
            }
        } else if (stakerConstraints_ == StakerConstraints.EOA) {
            _requireAccountIsVerifiedEOA(to);
        }

        if (amount == 0) {
            revert ERC20WrapperBase__AmountMustBeGreaterThanZero();
        }

        IERC20 wrappedCollection_ = IERC20(getWrappedCollectionAddress());

        uint256 tokenBalance = wrappedCollection_.balanceOf(_msgSender());
        if (tokenBalance < amount) {
            revert ERC20WrapperBase__InsufficientBalanceOfWrappedToken();
        }
        
        _onStake(amount, msg.value);
        emit Staked(to, amount);
        SafeERC20.safeTransferFrom(wrappedCollection_, _msgSender(), address(this), amount);
        _doTokenMint(to, amount);
    }

    /// @notice Allows holders of this wrapper ERC20 token to unstake and receive the original wrapped tokens.
    /// 
    /// Throws when amount is zero.
    /// Throws when caller does not have a balance greater than or equal to amount of this wrapper collection.
    /// Throws when inheriting contract reverts in the _onUnstake function (for example, in a pay to unstake scenario).
    /// Throws when _burn function reverts (for example, when additional burn validation logic reverts).
    /// Throws when safeTransferFrom function reverts.
    ///
    /// Postconditions:
    /// ---------------
    /// The specified amount of wrapper token has been burned.
    /// The specified amount of wrapped token with the same id has been transferred to the caller.
    /// An `Unstaked` event has been emitted.
    function unstake(uint256 amount) public virtual payable override nonReentrant {
        if (amount == 0) {
            revert ERC20WrapperBase__AmountMustBeGreaterThanZero();
        }

        uint256 tokenBalance = _getBalanceOf(_msgSender());
        if (tokenBalance < amount) {
            revert ERC20WrapperBase__InsufficientBalanceOfWrappingToken();
        }

        _onUnstake(amount, msg.value);
        emit Unstaked(_msgSender(), amount);
        _doTokenBurn(_msgSender(), amount);
        SafeERC20.safeTransfer(IERC20(getWrappedCollectionAddress()), _msgSender(), amount);
    }

    /// @notice Returns true if the specified token id and amount is available to be unstaked, false otherwise.
    /// @dev This should be overridden in most cases by inheriting contracts to implement the proper constraints.
    /// In the base implementation, tokens are available to be unstaked if the contract's balance of 
    /// the wrapped token is greater than or equal to amount.
    function canUnstake(uint256 amount) public virtual view override returns (bool) {
        return IERC20(getWrappedCollectionAddress()).balanceOf(address(this)) >= amount;
    }

    /// @notice Returns the staker constraints that are currently in effect.
    function getStakerConstraints() public view override returns (StakerConstraints) {
        return stakerConstraints;
    }

    /// @notice Returns the address of the wrapped ERC20 contract.
    function getWrappedCollectionAddress() public virtual view override returns (address);

    /// @dev Optional logic hook that fires during stake transaction.
    function _onStake(uint256 /*amount*/, uint256 value) internal virtual {
        if(value > 0) {
            revert ERC20WrapperBase__DefaultImplementationOfStakeDoesNotAcceptPayment();
        }
    }

    /// @dev Optional logic hook that fires during unstake transaction.
    function _onUnstake(uint256 /*amount*/, uint256 value) internal virtual {
        if(value > 0) {
            revert ERC20WrapperBase__DefaultImplementationOfUnstakeDoesNotAcceptPayment();
        }
    }

    function _validateWrappedCollectionAddress(address wrappedCollectionAddress_) internal view {
        if(wrappedCollectionAddress_ == address(0) || wrappedCollectionAddress_.code.length == 0) {
            revert ERC20WrapperBase__InvalidERC20Collection();
        }
    }

    function _requireAccountIsVerifiedEOA(address account) internal view virtual;

    function _doTokenMint(address to, uint256 amount) internal virtual;

    function _doTokenBurn(address from, uint256 amount) internal virtual;

    function _getBalanceOf(address account) internal view virtual returns (uint256);
}

/**
 * @title ERC20CW
 * @author Limit Break, Inc.
 * @notice Constructable ERC20C Wrapper Contract implementation
 */
abstract contract ERC20CW is ERC20WrapperBase, ERC20C {

    IERC20 private immutable wrappedCollectionImmutable;

    constructor(address wrappedCollectionAddress_) {
        _validateWrappedCollectionAddress(wrappedCollectionAddress_);
        wrappedCollectionImmutable = IERC20(wrappedCollectionAddress_);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return 
        interfaceId == type(ICreatorTokenWrapperERC20).interfaceId || 
        interfaceId == type(ICreatorToken).interfaceId || 
        interfaceId == type(ICreatorTokenLegacy).interfaceId || 
        super.supportsInterface(interfaceId);
    }

    function getWrappedCollectionAddress() public virtual view override returns (address) {
        return address(wrappedCollectionImmutable);
    }

    function _requireAccountIsVerifiedEOA(address account) internal view virtual override {
        address validator = getTransferValidator();

        if(validator != address(0)) {
            if(!IEOARegistry(validator).isVerifiedEOA(account)) {
                revert ERC20WrapperBase__CallerSignatureNotVerifiedInEOARegistry();
            }
        }
    }

    function _doTokenMint(address to, uint256 amount) internal virtual override {
        _mint(to, amount);
    }

    function _doTokenBurn(address from, uint256 amount) internal virtual override {
        _burn(from, amount);
    }

    function _getBalanceOf(address account) internal view virtual override returns (uint256) {
        return balanceOf(account);
    }
}

/**
 * @title ERC20CWInitializable
 * @author Limit Break, Inc.
 * @notice Initializable ERC20C Wrapper Contract implementation to allow for EIP-1167 clones.
 */
abstract contract ERC20CWInitializable is ERC20WrapperBase, ERC20CInitializable {

    error ERC20CWInitializable__AlreadyInitializedWrappedCollection();

    /// @dev Points to an external ERC20 contract that will be wrapped via staking.
    IERC20 private wrappedCollection;

    bool private _wrappedCollectionInitialized;

    function initializeWrappedCollectionAddress(address wrappedCollectionAddress_) public {
        _requireCallerIsContractOwner();

        if(_wrappedCollectionInitialized) {
            revert ERC20CWInitializable__AlreadyInitializedWrappedCollection();
        }

        _wrappedCollectionInitialized = true;

        _validateWrappedCollectionAddress(wrappedCollectionAddress_);
        wrappedCollection = IERC20(wrappedCollectionAddress_);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return 
        interfaceId == type(ICreatorTokenWrapperERC20).interfaceId || 
        interfaceId == type(ICreatorToken).interfaceId || 
        interfaceId == type(ICreatorTokenLegacy).interfaceId || 
        super.supportsInterface(interfaceId);
    }

    /// @notice Returns the address of the wrapped ERC20 contract.
    function getWrappedCollectionAddress() public virtual view override returns (address) {
        return address(wrappedCollection);
    }

    function _requireAccountIsVerifiedEOA(address account) internal view virtual override {
        address validator = getTransferValidator();

        if(validator != address(0)) {
            if(!IEOARegistry(validator).isVerifiedEOA(account)) {
                revert ERC20WrapperBase__CallerSignatureNotVerifiedInEOARegistry();
            }
        }
    }

    function _doTokenMint(address to, uint256 amount) internal virtual override {
        _mint(to, amount);
    }

    function _doTokenBurn(address from, uint256 amount) internal virtual override {
        _burn(from, amount);
    }

    function _getBalanceOf(address account) internal view virtual override returns (uint256) {
        return balanceOf(account);
    }
}