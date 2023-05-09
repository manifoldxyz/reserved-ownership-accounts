// SPDX-License-Identifier: CC0-1.0

pragma solidity ^0.8.13;

/// @author: manifold.xyz

import {IERC1271} from "openzeppelin/interfaces/IERC1271.sol";
import {SignatureChecker} from "openzeppelin/utils/cryptography/SignatureChecker.sol";
import {IERC165} from "openzeppelin/utils/introspection/IERC165.sol";
import {ERC165Checker} from "openzeppelin/utils/introspection/ERC165Checker.sol";
import {IERC721} from "openzeppelin/token/ERC721/IERC721.sol";
import {IERC721Receiver} from "openzeppelin/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "openzeppelin/token/ERC1155/IERC1155Receiver.sol";
import {Initializable} from "openzeppelin/proxy/utils/Initializable.sol";
import {Ownable} from "openzeppelin/access/Ownable.sol";
import {IERC1967Account} from "./IERC1967Account.sol";

import {IAccount} from "../../interfaces/IAccount.sol";

/**
 * @title ERC1967AccountImplementation
 * @notice A lightweight, upgradeable smart contract wallet implementation
 */
contract ERC1967AccountImplementation is
    IAccount,
    IERC165,
    IERC721Receiver,
    IERC1155Receiver,
    IERC1967Account,
    IERC1271,
    Initializable,
    Ownable
{
    address public registry;

    constructor() {
        _disableInitializers();
    }

    function initialize() external initializer {
        registry = msg.sender;
        _transferOwnership(registry);
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return (interfaceId == type(IAccount).interfaceId ||
            interfaceId == type(IERC1967Account).interfaceId ||
            interfaceId == type(IERC1155Receiver).interfaceId ||
            interfaceId == type(IERC721Receiver).interfaceId ||
            interfaceId == type(IERC165).interfaceId);
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes memory
    ) public pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) public pure returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    /**
     * @dev {See IERC1967Account-executeCall}
     */
    function executeCall(
        address _target,
        uint256 _value,
        bytes calldata _data
    ) external payable override onlyOwner returns (bytes memory _result) {
        bool success;
        // solhint-disable-next-line avoid-low-level-calls
        (success, _result) = _target.call{value: _value}(_data);
        require(success, string(_result));
        emit TransactionExecuted(_target, _value, _data);
        return _result;
    }

    /**
     * @dev {See IAccount-setOwner}
     */
    function setOwner(address _owner) external override onlyOwner {
        _transferOwnership(_owner);
    }

    receive() external payable {}

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        if (owner() == registry) {
            return IERC1271(registry).isValidSignature(hash, signature);
        }

        bool isValid = SignatureChecker.isValidSignatureNow(owner(), hash, signature);
        if (isValid) {
            return IERC1271.isValidSignature.selector;
        }

        return "";
    }
}
