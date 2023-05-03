// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {IAccountRegistry} from "../../../../src/interfaces/IAccountRegistry.sol";
import {AccountRegistryImplementation} from "../../../../src/examples/registry/AccountRegistryImplementation.sol";
import {MockAccount} from "../../../mocks/MockAccount.sol";
import {MockSigner} from "../../../mocks/MockSigner.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract AccountRegistryTest is Test {
    AccountRegistryImplementation internal registry;
    MockAccount internal implementation;
    address internal signer;
    uint256 internal signerPrivateKey;
    address internal accountOwner;

    function setUp() public {
        signerPrivateKey = 0x1337;
        signer = vm.addr(signerPrivateKey);
        accountOwner = vm.addr(1);
        implementation = new MockAccount();
        registry = new AccountRegistryImplementation(address(implementation));
        registry.setSigner(signer);
    }

    function testAccount() public {
        uint256 salt = 1;

        address account = registry.account(salt);

        assertNotEq(account, address(0));
    }

    function testCreateAccount() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_DifferentSender() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(vm.addr(2));

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_RevertWhen_DifferentSigner() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_RevertWhen_PastExpiration() public {
        vm.warp(100);

        uint256 salt = 1;
        uint256 expiration = block.timestamp - 1;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_RevertWhen_DifferentMessageAccount() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", vm.addr(2), salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_RevertWhen_DifferentMessageSalt() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, "2", expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_RevertWhen_DifferentMessageExpiration() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n84",
                accountOwner,
                salt,
                block.timestamp
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_RevertWhen_InitializationFails() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("InitializationFailed()"))));

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", false)
        );
    }

    function testCreateAccount_ContractSigner() public {
        uint256 signerOwnerPrivateKey = 0x2;
        vm.prank(vm.addr(signerOwnerPrivateKey));
        MockSigner mockSigner = new MockSigner();
        mockSigner.mockIsValid(true);
        registry.setSigner(address(mockSigner));

        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerOwnerPrivateKey, message);

        vm.prank(accountOwner);

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_ContractSigner_RevertWhen_InvalidSignature() public {
        uint256 signerOwnerPrivateKey = 0x2;
        vm.prank(vm.addr(signerOwnerPrivateKey));
        MockSigner mockSigner = new MockSigner();
        registry.setSigner(address(mockSigner));

        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerOwnerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_ContractSigner_RevertWhen_DifferentMessageAccount() public {
        uint256 signerOwnerPrivateKey = 0x2;
        vm.prank(vm.addr(signerOwnerPrivateKey));
        MockSigner mockSigner = new MockSigner();
        mockSigner.mockIsValid(true);
        registry.setSigner(address(mockSigner));

        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", vm.addr(2), salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerOwnerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_ContractSigner_RevertWhen_DifferentMessageSalt() public {
        uint256 signerOwnerPrivateKey = 0x2;
        vm.prank(vm.addr(signerOwnerPrivateKey));
        MockSigner mockSigner = new MockSigner();
        mockSigner.mockIsValid(true);
        registry.setSigner(address(mockSigner));

        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, "2", expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerOwnerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function testCreateAccount_ContractSigner_RevertWhen_DifferentMessageExpiration() public {
        uint256 signerOwnerPrivateKey = 0x2;
        vm.prank(vm.addr(signerOwnerPrivateKey));
        MockSigner mockSigner = new MockSigner();
        mockSigner.mockIsValid(true);
        registry.setSigner(address(mockSigner));

        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n84",
                accountOwner,
                salt,
                block.timestamp
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerOwnerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );
    }

    function test_AddressesMatch() public {
        uint256 salt = 1;

        address account = registry.account(salt);

        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);

        address created = registry.createAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v),
            abi.encodeWithSignature("initialize(bool)", true)
        );

        assertEq(created, account);
    }

    function test_Initialize_Reverts() public {
        vm.expectRevert("Initializable: contract is already initialized");

        registry.initialize(address(implementation), accountOwner);
    }
}
