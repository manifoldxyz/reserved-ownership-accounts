// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {IERC165} from "openzeppelin/utils/introspection/IERC165.sol";
import {IERC721} from "openzeppelin/token/ERC721/IERC721.sol";
import {IERC1271} from "openzeppelin/interfaces/IERC1271.sol";
import {SignatureChecker} from "openzeppelin/utils/cryptography/SignatureChecker.sol";

import {IAccount} from "./interfaces/IAccount.sol";

contract Account is IERC165, IERC1271, IAccount {
    address public owner;

    receive() external payable {}

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not owner");
        _;
    }

    function initialize() external {
        require(owner == address(0), "Already initialized");
        owner = msg.sender;
    }

    function executeCall(
        address to,
        uint256 value,
        bytes calldata data
    ) external payable onlyOwner returns (bytes memory result) {
        require(msg.sender == owner, "Not owner");

        bool success;
        (success, result) = to.call{value: value}(data);

        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }

        emit TransactionExecuted(to, value, data);
    }

    function setOwner(address newOwner) external override onlyOwner {
        owner = newOwner;
    }

    function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
        return (interfaceId == type(IERC165).interfaceId ||
            interfaceId == type(IAccount).interfaceId);
    }

    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view returns (bytes4 magicValue) {
        bool isValid = SignatureChecker.isValidSignatureNow(owner, hash, signature);

        if (isValid) {
            return IERC1271.isValidSignature.selector;
        }

        return "";
    }
}
