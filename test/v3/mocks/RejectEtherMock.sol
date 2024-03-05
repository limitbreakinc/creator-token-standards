// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

contract RejectEtherMock {
    fallback() external payable {
        revert("Receiving ETH not permitted");
    }

    receive() external payable {
        revert("Receiving ETH not permitted");
    }
}
