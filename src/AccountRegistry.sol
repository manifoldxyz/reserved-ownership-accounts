// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @author: manifold.xyz

import {Create2} from "openzeppelin/utils/Create2.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {Ownable} from "openzeppelin/access/Ownable.sol";

import {IAccountRegistry} from "./interfaces/IAccountRegistry.sol";
import {IAccount} from "./interfaces/IAccount.sol";
import {AccountBytecode} from "./lib/AccountBytecode.sol";

contract AccountRegistry is Ownable, IAccountRegistry {
    using ECDSA for bytes32;

    error InitializationFailed();
    error Unauthorized();

    address private signer;

    function createAccount(
        address implementation,
        bytes32 salt,
        AuthorizationParams calldata auth,
        bytes calldata initData
    ) external returns (address) {
        _verify(salt, auth);

        bytes memory code = AccountBytecode.createCode(implementation);

        address _account = Create2.computeAddress(salt, keccak256(code));

        if (_account.code.length != 0) return _account;

        _account = Create2.deploy(0, bytes32(salt), code);

        if (initData.length != 0) {
            (bool success, ) = _account.call(initData);
            if (!success) revert InitializationFailed();
        }

        emit AccountCreated(_account, implementation, salt);

        return _account;
    }

    function account(address implementation, bytes32 salt) external view returns (address) {
        bytes memory code = AccountBytecode.createCode(implementation);
        return Create2.computeAddress(salt, keccak256(code));
    }

    function setSigner(address newSigner) external onlyOwner {
        signer = newSigner;
    }

    function _verify(bytes32 salt, AuthorizationParams calldata auth) internal view {
        bytes32 expectedMessage = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", msg.sender, salt, auth.expiration)
        );
        address messageSigner = auth.message.recover(auth.signature);

        if (
            auth.message != expectedMessage ||
            messageSigner != signer ||
            auth.expiration < block.timestamp
        ) revert Unauthorized();
    }
}
