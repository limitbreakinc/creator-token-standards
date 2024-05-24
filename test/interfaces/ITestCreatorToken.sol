// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "src/interfaces/ICreatorToken.sol";
import "src/adventures/Quest.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

interface ITestCreatorToken is IERC721, ICreatorToken {
    function DEFAULT_TRANSFER_VALIDATOR() external view returns (address);
    
    function mint(address, uint256) external;
    function mint(address, uint256, uint256) external;
    
    function setAutomaticApprovalOfTransfersFromValidator(bool autoApprove) external;

    function setApprovalForAll(address operator, bool _approved) external;
    function isApprovedForAll(address owner, address operator) external view returns (bool);
    function approve(address operator, uint256 _allowance) external;
    function allowance(address owner, address spender) external view returns (uint256);

    function supportsInterface(bytes4 interfaceId) external view returns (bool);

    // Adventure Stuff

    /**
     * @notice Transfers a player's token if they have opted into an authorized, whitelisted adventure.
     */
    function adventureTransferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @notice Safe transfers a player's token if they have opted into an authorized, whitelisted adventure.
     */
    function adventureSafeTransferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @notice Burns a player's token if they have opted into an authorized, whitelisted adventure.
     */
    function adventureBurn(uint256 tokenId) external;

    /**
     * @notice Enters a player's token into a quest if they have opted into an authorized, whitelisted adventure.
     */
    function enterQuest(uint256 tokenId, uint256 questId) external;

    /**
     * @notice Exits a player's token from a quest if they have opted into an authorized, whitelisted adventure.
     */
    function exitQuest(uint256 tokenId, uint256 questId) external;

    /**
     * @notice Returns the number of quests a token is actively participating in for a specified adventure
     */
    function getQuestCount(uint256 tokenId, address adventure) external view returns (uint256);

    /**
     * @notice Returns the amount of time a token has been participating in the specified quest
     */
    function getTimeOnQuest(uint256 tokenId, address adventure, uint256 questId) external view returns (uint256);

    /**
     * @notice Returns whether or not a token is currently participating in the specified quest as well as the time it was started and the quest index
     */
    function isParticipatingInQuest(uint256 tokenId, address adventure, uint256 questId) external view returns (bool participatingInQuest, uint256 startTimestamp, uint256 index);

    /**
     * @notice Returns a list of all active quests for the specified token id and adventure
     */
    function getActiveQuests(uint256 tokenId, address adventure) external view returns (Quest[] memory activeQuests);

    function setAdventuresApprovedForAll(address operator, bool approved) external;

    /// @notice Similar to {IERC721-isApprovedForAll}, but for special in-game adventures only
    function areAdventuresApprovedForAll(address owner_, address operator) external view returns (bool);
}
