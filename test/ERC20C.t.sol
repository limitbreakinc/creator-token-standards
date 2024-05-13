// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "./mocks/ERC20CMock.sol";
import "./mocks/ClonerMock.sol";
import "./CreatorTokenFungible.t.sol";

contract ERC20CTest is CreatorTokenFungibleTest {
    uint8 private constant DEFAULT_DECIMALS = 18;

    ERC20CMock public tokenMock;

    function setUp() public virtual override {
        super.setUp();

        tokenMock = new ERC20CMock(DEFAULT_DECIMALS);
        //TODO: tokenMock.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Two, 0);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.startPrank(creator);
        ITestCreatorToken token = ITestCreatorToken(address(new ERC20CMock(DEFAULT_DECIMALS)));
        vm.stopPrank();
        return token;
    }

    function _mintToken(address tokenAddress, address to, uint256 amount) internal virtual override {
        vm.startPrank(to);
        ERC20CMock(tokenAddress).mint(to, amount);
        vm.stopPrank();
    }

    function testTokenMetadata() public {
        assertEq(tokenMock.name(), "ERC20CMock");
        assertEq(tokenMock.symbol(), "E20CM");
        assertEq(tokenMock.decimals(), DEFAULT_DECIMALS);
    }

    function testSupportedTokenInterfaces() public {
        assertEq(tokenMock.supportsInterface(type(ICreatorToken).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC20).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC20Metadata).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC165).interfaceId), true);
    }

    function testGetTransferValidationFunction() public override {
        (bytes4 functionSignature, bool isViewFunction) = tokenMock.getTransferValidationFunction();

        assertEq(functionSignature, bytes4(keccak256("validateTransfer(address,address,address,uint256,uint256)")));
        assertEq(isViewFunction, false);
    }

    function testTransferValidatorTokenTypeIsSet() public {
        CollectionSecurityPolicyV3 memory securityPolicy = validator.getCollectionSecurityPolicy(address(tokenMock));
        assertEq(securityPolicy.tokenType, TOKEN_TYPE_ERC20);
    }
}

contract ERC20CWInitializableTest is CreatorTokenFungibleTest {
    uint8 private constant DEFAULT_DECIMALS = 18;

    ClonerMock cloner;

    ERC20CInitializableMock public tokenMock;
    ERC20CInitializableMock public referenceTokenMock;

    function setUp() public virtual override {
        super.setUp();

        cloner = new ClonerMock();

        referenceTokenMock = new ERC20CInitializableMock();

        bytes4[] memory initializationSelectors = new bytes4[](1);
        bytes[] memory initializationArguments = new bytes[](1);

        initializationSelectors[0] = referenceTokenMock.initializeERC20.selector;
        initializationArguments[0] = abi.encode("ERC20CInitializableMock", "ERC20CIM", DEFAULT_DECIMALS);

        tokenMock = ERC20CInitializableMock(
            cloner.cloneContract(
                address(referenceTokenMock), address(this), initializationSelectors, initializationArguments
            )
        );

        //TODO: tokenMock.setToCustomValidatorAndSecurityPolicy(address(validator), TransferSecurityLevels.Two, 0);
    }

    function _deployNewToken(address creator) internal virtual override returns (ITestCreatorToken) {
        vm.startPrank(creator);

        bytes4[] memory initializationSelectors = new bytes4[](1);
        bytes[] memory initializationArguments = new bytes[](1);

        initializationSelectors[0] = referenceTokenMock.initializeERC20.selector;
        initializationArguments[0] = abi.encode("ERC20CInitializableMock", "ERC20CIM", DEFAULT_DECIMALS);

        ITestCreatorToken token = ITestCreatorToken(
            cloner.cloneContract(address(referenceTokenMock), creator, initializationSelectors, initializationArguments)
        );
        vm.stopPrank();
        return token;
    }

    function _mintToken(address tokenAddress, address to, uint256 amount) internal virtual override {
        vm.startPrank(to);
        ERC20CInitializableMock(tokenAddress).mint(to, amount);
        vm.stopPrank();
    }

    function testSupportedTokenInterfaces() public {
        assertEq(tokenMock.supportsInterface(type(ICreatorToken).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC20).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC20Metadata).interfaceId), true);
        assertEq(tokenMock.supportsInterface(type(IERC165).interfaceId), true);
    }

    function testGetTransferValidationFunction() public override {
        (bytes4 functionSignature, bool isViewFunction) = tokenMock.getTransferValidationFunction();

        assertEq(functionSignature, bytes4(keccak256("validateTransfer(address,address,address,uint256,uint256)")));
        assertEq(isViewFunction, false);
    }

    function testInitializeAlreadyInitialized(string memory badName, string memory badSymbol, uint8 badDecimals) public {
        vm.expectRevert(ERC20OpenZeppelinInitializable.ERC20OpenZeppelinInitializable__AlreadyInitializedERC20.selector);
        tokenMock.initializeERC20(badName, badSymbol, badDecimals);
    }

    function testRevertsWhenInitializingOwnerAgain(address badOwner) public {
        vm.expectRevert(OwnableInitializable.InitializableOwnable__OwnerAlreadyInitialized.selector);
        tokenMock.initializeOwner(badOwner);
    }

    function testTransferValidatorTokenTypeIsSet() public {
        CollectionSecurityPolicyV3 memory securityPolicy = validator.getCollectionSecurityPolicy(address(tokenMock));
        assertEq(securityPolicy.tokenType, TOKEN_TYPE_ERC20);
    }
}
