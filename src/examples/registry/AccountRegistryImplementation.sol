// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

/// @author: manifold.xyz

import {Create2} from "openzeppelin/utils/Create2.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {Ownable} from "openzeppelin/access/Ownable.sol";
import {Initializable} from "openzeppelin/proxy/utils/Initializable.sol";
import {IERC1271} from "openzeppelin/interfaces/IERC1271.sol";
import {SignatureChecker} from "openzeppelin/utils/cryptography/SignatureChecker.sol";

import {Address} from "../../lib/Address.sol";
import {IAccountRegistry} from "../../interfaces/IAccountRegistry.sol";
import {ERC1167ProxyBytecode} from "../../lib/ERC1167ProxyBytecode.sol";

contract AccountRegistryImplementation is Ownable, Initializable, IAccountRegistry {
    using Address for address;
    using ECDSA for bytes32;

    struct Signer {
        address account;
        bool isContract;
    }

    error InitializationFailed();
    error ClaimFailed();
    error Unauthorized();

    address public accountImplementation;
    bytes public accountInitData;
    Signer public signer;

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address owner,
        address accountImplementation_,
        bytes calldata accountInitData_
    ) external initializer {
        _transferOwnership(owner);
        accountImplementation = accountImplementation_;
        accountInitData = accountInitData_;
    }

    /**
     * @dev See {IAccountRegistry-createAccount}
     */
    function createAccount(uint256 salt) external override returns (address) {
        bytes memory code = ERC1167ProxyBytecode.createCode(accountImplementation);
        address _account = Create2.computeAddress(bytes32(salt), keccak256(code));

        if (_account.isDeployed()) return _account;

        _account = Create2.deploy(0, bytes32(salt), code);

        (bool success, ) = _account.call(accountInitData);
        if (!success) revert InitializationFailed();

        emit AccountCreated(_account, accountImplementation, salt);

        return _account;
    }

    /**
     * @dev See {IAccountRegistry-claimAccount}
     */
    function claimAccount(
        address owner,
        uint256 salt,
        uint256 expiration,
        bytes32 message,
        bytes calldata signature
    ) external override returns (address) {
        _verify(owner, salt, expiration, message, signature);
        address _account = this.createAccount(salt);

        (bool success, ) = _account.call(abi.encodeWithSignature("setOwner(address)", owner));
        if (!success) revert ClaimFailed();

        emit AccountClaimed(_account, owner);
        return _account;
    }

    /**
     * @dev See {IAccountRegistry-account}
     */
    function account(uint256 salt) external view override returns (address) {
        bytes memory code = ERC1167ProxyBytecode.createCode(accountImplementation);
        return Create2.computeAddress(bytes32(salt), keccak256(code));
    }

    /**
     * @dev See {IAccountRegistry-isValidSignature}
     */
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        bytes32 expectedHash = keccak256(abi.encodePacked(hash, msg.sender));
        bool isValid = SignatureChecker.isValidSignatureNow(
            signer.account,
            expectedHash,
            signature
        );
        if (isValid) {
            return IERC1271.isValidSignature.selector;
        }

        return "";
    }

    function updateSigner(address newSigner) external onlyOwner {
        uint32 signerSize;
        assembly {
            signerSize := extcodesize(newSigner)
        }
        signer.account = newSigner;
        signer.isContract = signerSize > 0;
    }

    function _verify(
        address owner,
        uint256 salt,
        uint256 expiration,
        bytes32 message,
        bytes calldata signature
    ) internal view {
        address signatureAccount;

        if (signer.isContract) {
            if (!SignatureChecker.isValidSignatureNow(signer.account, message, signature))
                revert Unauthorized();
        } else {
            signatureAccount = message.recover(signature);
        }

        bytes32 expectedMessage = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", owner, salt, expiration)
        );

        if (
            message != expectedMessage ||
            (!signer.isContract && signatureAccount != signer.account) ||
            (expiration != 0 && expiration < block.timestamp)
        ) revert Unauthorized();
    }
}
