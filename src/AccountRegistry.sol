// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @author: manifold.xyz

import {Create2} from "openzeppelin/utils/Create2.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {Ownable} from "openzeppelin/access/Ownable.sol";
import {IERC1271} from "openzeppelin/interfaces/IERC1271.sol";
import {SignatureChecker} from "openzeppelin/utils/cryptography/SignatureChecker.sol";

import {Address} from "./lib/Address.sol";
import {IAccountRegistry} from "./interfaces/IAccountRegistry.sol";
import {IAccount} from "./interfaces/IAccount.sol";
import {ERC1167ProxyBytecode} from "./lib/ERC1167ProxyBytecode.sol";

contract AccountRegistry is Ownable, IAccountRegistry {
    using Address for address;
    using ECDSA for bytes32;

    error InitializationFailed();
    error Unauthorized();

    Signer private signer;

    function createAccount(
        address implementation,
        bytes32 salt,
        AuthorizationParams calldata auth,
        bytes calldata initData
    ) external returns (address) {
        _verify(salt, auth);

        bytes memory code = ERC1167ProxyBytecode.createCode(implementation);

        address _account = Create2.computeAddress(salt, keccak256(code));

        if (_account.isDeployed()) return _account;

        _account = Create2.deploy(0, salt, code);

        if (initData.length != 0) {
            (bool success, ) = _account.call(initData);
            if (!success) revert InitializationFailed();
        }

        emit AccountCreated(_account, implementation, salt);

        return _account;
    }

    function account(address implementation, bytes32 salt) external view returns (address) {
        bytes memory code = ERC1167ProxyBytecode.createCode(implementation);
        return Create2.computeAddress(salt, keccak256(code));
    }

    function setSigner(address newSigner) external onlyOwner {
        uint32 signerSize;
        assembly {
            signerSize := extcodesize(newSigner)
        }
        signer.account = newSigner;
        signer.isContract = signerSize > 0;
    }

    function _verify(bytes32 salt, AuthorizationParams calldata auth) internal view {
        address signatureAccount;

        if (signer.isContract) {
            if (!SignatureChecker.isValidSignatureNow(signer.account, auth.message, auth.signature))
                revert Unauthorized();
        } else {
            signatureAccount = auth.message.recover(auth.signature);
        }

        bytes32 expectedMessage = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", msg.sender, salt, auth.expiration)
        );

        if (
            auth.message != expectedMessage ||
            (!signer.isContract && signatureAccount != signer.account) ||
            auth.expiration < block.timestamp
        ) revert Unauthorized();
    }
}
