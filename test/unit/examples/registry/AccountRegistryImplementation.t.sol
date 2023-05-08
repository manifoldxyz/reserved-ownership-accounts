// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {AccountRegistryImplementation} from "../../../../src/examples/registry/AccountRegistryImplementation.sol";
import {ERC1967AccountProxy} from "../../../../src/examples/account/ERC1967AccountProxy.sol";
import {ERC1967AccountImplementation} from "../../../../src/examples/account/ERC1967AccountImplementation.sol";
import {MockSigner} from "../../../mocks/MockSigner.sol";
import {Clones} from "openzeppelin/proxy/Clones.sol";

contract AccountRegistryTest is Test {
    AccountRegistryImplementation internal registry;
    ERC1967AccountImplementation internal implementation;
    ERC1967AccountProxy internal proxy;
    address internal signer;
    uint256 internal signerPrivateKey;
    address internal accountOwner;

    function setUp() public {
        signerPrivateKey = 0x1337;
        signer = vm.addr(signerPrivateKey);
        accountOwner = vm.addr(1);
        implementation = new ERC1967AccountImplementation();
        proxy = new ERC1967AccountProxy();
        registry = AccountRegistryImplementation(
            Clones.clone(address(new AccountRegistryImplementation()))
        );
        registry.initialize(address(proxy), address(implementation), address(this));
        registry.updateSigner(signer);
    }

    function testAccount() public {
        uint256 salt = 1;

        address account = registry.account(salt);

        assertNotEq(account, address(0));
    }

    function testclaimAccount() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);

        registry.claimAccount(accountOwner, salt, expiration, message, abi.encodePacked(r, s, v));
    }

    function testclaimAccount_DifferentSender() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(vm.addr(2));

        registry.claimAccount(accountOwner, salt, expiration, message, abi.encodePacked(r, s, v));
    }

    function testclaimAccount_RevertWhen_DifferentSigner() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.claimAccount(accountOwner, salt, expiration, message, abi.encodePacked(r, s, v));
    }

    function testclaimAccount_RevertWhen_PastExpiration() public {
        vm.warp(100);

        uint256 salt = 1;
        uint256 expiration = block.timestamp - 1;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.claimAccount(accountOwner, salt, expiration, message, abi.encodePacked(r, s, v));
    }

    function testclaimAccount_RevertWhen_DifferentMessageAccount() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", vm.addr(2), salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.claimAccount(accountOwner, salt, expiration, message, abi.encodePacked(r, s, v));
    }

    function testclaimAccount_RevertWhen_DifferentMessageSalt() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, "2", expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.claimAccount(accountOwner, salt, expiration, message, abi.encodePacked(r, s, v));
    }

    function testclaimAccount_RevertWhen_DifferentMessageExpiration() public {
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

        registry.claimAccount(accountOwner, salt, expiration, message, abi.encodePacked(r, s, v));
    }

    function testclaimAccount_ContractSigner() public {
        uint256 signerOwnerPrivateKey = 0x2;
        vm.prank(vm.addr(signerOwnerPrivateKey));
        MockSigner mockSigner = new MockSigner();
        mockSigner.mockIsValid(true);
        registry.updateSigner(address(mockSigner));

        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerOwnerPrivateKey, message);

        vm.prank(accountOwner);

        registry.claimAccount(accountOwner, salt, expiration, message, abi.encodePacked(r, s, v));
    }

    function testclaimAccount_ContractSigner_RevertWhen_InvalidSignature() public {
        uint256 signerOwnerPrivateKey = 0x2;
        vm.prank(vm.addr(signerOwnerPrivateKey));
        MockSigner mockSigner = new MockSigner();
        registry.updateSigner(address(mockSigner));

        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerOwnerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.claimAccount(accountOwner, salt, expiration, message, abi.encodePacked(r, s, v));
    }

    function testclaimAccount_ContractSigner_RevertWhen_DifferentMessageAccount() public {
        uint256 signerOwnerPrivateKey = 0x2;
        vm.prank(vm.addr(signerOwnerPrivateKey));
        MockSigner mockSigner = new MockSigner();
        mockSigner.mockIsValid(true);
        registry.updateSigner(address(mockSigner));

        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", vm.addr(2), salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerOwnerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.claimAccount(accountOwner, salt, expiration, message, abi.encodePacked(r, s, v));
    }

    function testclaimAccount_ContractSigner_RevertWhen_DifferentMessageSalt() public {
        uint256 signerOwnerPrivateKey = 0x2;
        vm.prank(vm.addr(signerOwnerPrivateKey));
        MockSigner mockSigner = new MockSigner();
        mockSigner.mockIsValid(true);
        registry.updateSigner(address(mockSigner));

        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, "2", expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerOwnerPrivateKey, message);

        vm.prank(accountOwner);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("Unauthorized()"))));

        registry.claimAccount(accountOwner, salt, expiration, message, abi.encodePacked(r, s, v));
    }

    function testclaimAccount_ContractSigner_RevertWhen_DifferentMessageExpiration() public {
        uint256 signerOwnerPrivateKey = 0x2;
        vm.prank(vm.addr(signerOwnerPrivateKey));
        MockSigner mockSigner = new MockSigner();
        mockSigner.mockIsValid(true);
        registry.updateSigner(address(mockSigner));

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

        registry.claimAccount(accountOwner, salt, expiration, message, abi.encodePacked(r, s, v));
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

        address created = registry.claimAccount(
            accountOwner,
            salt,
            expiration,
            message,
            abi.encodePacked(r, s, v)
        );

        assertEq(created, account);
    }

    function test_Initialize_Reverts() public {
        vm.expectRevert("Initializable: contract is already initialized");

        registry.initialize(address(implementation), address(implementation), accountOwner);
    }
}
