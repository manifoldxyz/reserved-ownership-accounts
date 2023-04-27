// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {IAccountRegistry} from "../../src/interfaces/IAccountRegistry.sol";
import {AccountRegistry} from "../../src/AccountRegistry.sol";
import {MockAccount} from "../mocks/MockAccount.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract AccountRegistryTest is Test {
    AccountRegistry internal registry;
    MockAccount internal implementation;
    address internal signer;
    uint256 internal signerPrivateKey;
    address internal accountOwner;

    function setUp() public {
        signerPrivateKey = 0x1337;
        signer = vm.addr(signerPrivateKey);
        accountOwner = vm.addr(1);
        registry = new AccountRegistry();
        registry.setSigner(signer);
        implementation = new MockAccount();
    }

    function testAccount() public {
        uint256 chainId = 1;
        bytes32 salt = "1";

        address account = registry.account(address(implementation), chainId, salt);

        assertNotEq(address(account), address(0));
    }

    function testCreateAccount() public {
        uint256 chainId = 1;
        bytes32 salt = "1";
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n52", accountOwner, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);
        IAccountRegistry.AuthorizationParams memory auth = IAccountRegistry.AuthorizationParams({
            expiration: expiration,
            message: message,
            signature: abi.encodePacked(r, s, v)
        });

        vm.prank(accountOwner);

        registry.createAccount(
            address(implementation),
            chainId,
            salt,
            auth,
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_RevertWhen_DifferentSigner() public {
        uint256 chainId = 1;
        bytes32 salt = "1";
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n52", msg.sender, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, message);
        IAccountRegistry.AuthorizationParams memory auth = IAccountRegistry.AuthorizationParams({
            expiration: expiration,
            message: message,
            signature: abi.encodePacked(r, s, v)
        });

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.createAccount(
            address(implementation),
            chainId,
            salt,
            auth,
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_RevertWhen_PastExpiration() public {
        uint256 chainId = 1;
        bytes32 salt = "1";
        uint256 expiration = block.timestamp - 1;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n52", accountOwner, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);
        IAccountRegistry.AuthorizationParams memory auth = IAccountRegistry.AuthorizationParams({
            expiration: expiration,
            message: message,
            signature: abi.encodePacked(r, s, v)
        });

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.createAccount(
            address(implementation),
            chainId,
            salt,
            auth,
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_RevertWhen_DifferentMessage() public {
        uint256 chainId = 1;
        bytes32 salt = "1";
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n52", accountOwner, block.timestamp)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);
        IAccountRegistry.AuthorizationParams memory auth = IAccountRegistry.AuthorizationParams({
            expiration: expiration,
            message: message,
            signature: abi.encodePacked(r, s, v)
        });

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.createAccount(
            address(implementation),
            chainId,
            salt,
            auth,
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_RevertWhen_InitializationFails() public {
        uint256 chainId = 1;
        bytes32 salt = "1";
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n52", accountOwner, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);
        IAccountRegistry.AuthorizationParams memory auth = IAccountRegistry.AuthorizationParams({
            expiration: expiration,
            message: message,
            signature: abi.encodePacked(r, s, v)
        });

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("InitializationFailed()"))));

        registry.createAccount(
            address(implementation),
            chainId,
            salt,
            auth,
            abi.encodeWithSignature("initialize(bool)", false)
        );
    }

    function test_AddressesMatch() public {
        uint256 chainId = 1;
        bytes32 salt = "1";

        address account = registry.account(address(implementation), chainId, salt);

        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n52", accountOwner, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);
        IAccountRegistry.AuthorizationParams memory auth = IAccountRegistry.AuthorizationParams({
            expiration: expiration,
            message: message,
            signature: abi.encodePacked(r, s, v)
        });

        vm.prank(accountOwner);

        address created = registry.createAccount(
            address(implementation),
            chainId,
            salt,
            auth,
            abi.encodeWithSignature("initialize(bool)", true)
        );

        assertEq(address(created), address(account));
    }
}