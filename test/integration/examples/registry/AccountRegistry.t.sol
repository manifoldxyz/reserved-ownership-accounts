// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {AccountRegistryImplementation} from "../../../../src/examples/registry/AccountRegistryImplementation.sol";
import {ERC1967AccountProxy} from "../../../../src/examples/account/ERC1967AccountProxy.sol";
import {ERC1967AccountImplementation} from "../../../../src/examples/account/ERC1967AccountImplementation.sol";
import {IAccountRegistry} from "../../../../src/interfaces/IAccountRegistry.sol";
import {Clones} from "openzeppelin/proxy/Clones.sol";
import {UniversalSigValidator} from "signature-validator/EIP6492.sol";

contract AccountRegistryTest is Test {
    AccountRegistryImplementation internal registry;
    ERC1967AccountImplementation internal accountImplementation;
    ERC1967AccountProxy internal accountImplementationProxy;
    address internal signer;
    uint256 internal signerPrivateKey;
    address internal accountOwner;

    function setUp() public {
        signerPrivateKey = 0x1337;
        signer = vm.addr(signerPrivateKey);
        accountOwner = vm.addr(1);
        accountImplementation = new ERC1967AccountImplementation();
        accountImplementationProxy = new ERC1967AccountProxy();
        registry = AccountRegistryImplementation(
            Clones.clone(address(new AccountRegistryImplementation()))
        );
        registry.initialize(
            address(this),
            address(accountImplementationProxy),
            abi.encodeWithSignature(
                "initialize(address,bytes)",
                accountImplementation,
                abi.encodeWithSignature("initialize()")
            )
        );
        registry.updateSigner(signer);
    }

    function testCreateAccount() public {
        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);

        ERC1967AccountImplementation account = ERC1967AccountImplementation(
            payable(
                registry.claimAccount(
                    accountOwner,
                    salt,
                    expiration,
                    message,
                    abi.encodePacked(r, s, v)
                )
            )
        );

        assertEq(account.owner(), accountOwner);
    }

    function testERC6492SignatureVerification() public {
        uint256 salt = 1;
        address accountAddress = registry.account(salt);
        bytes32 message = keccak256("Arbitrary message");
        bytes32 messageToSign = keccak256(abi.encodePacked(message, accountAddress));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, messageToSign);

        UniversalSigValidator universalSigValidator = new UniversalSigValidator();

        bytes32 erc6492DetectionSuffix = 0x6492649264926492649264926492649264926492649264926492649264926492;
        bytes memory _calldata = abi.encodeWithSelector(
            IAccountRegistry.createAccount.selector,
            salt
        );
        bytes memory sig = abi.encodePacked(
            abi.encode(address(registry), _calldata, abi.encodePacked(r, s, v)),
            erc6492DetectionSuffix
        );

        assertTrue(universalSigValidator.isValidSig(accountAddress, message, sig));
    }

    function testERC6492SignatureVerification_InvalidWhen_DifferentAccount() public {
        uint256 salt = 1;
        address accountAddress = registry.account(salt);
        bytes32 message = keccak256("Arbitrary message");
        bytes32 messageToSign = keccak256(abi.encodePacked(message, registry.account(2)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, messageToSign);

        UniversalSigValidator universalSigValidator = new UniversalSigValidator();

        bytes32 erc6492DetectionSuffix = 0x6492649264926492649264926492649264926492649264926492649264926492;
        bytes memory _calldata = abi.encodeWithSelector(
            IAccountRegistry.createAccount.selector,
            salt
        );
        bytes memory sig = abi.encodePacked(
            abi.encode(address(registry), _calldata, abi.encodePacked(r, s, v)),
            erc6492DetectionSuffix
        );

        assertFalse(universalSigValidator.isValidSig(accountAddress, message, sig));
    }

    function testUnclaimedAccountSignatureVerification() public {
        uint256 salt = 1;
        address accountAddress = registry.createAccount(salt);
        bytes32 message = keccak256("Arbitrary message");
        bytes32 messageToSign = keccak256(abi.encodePacked(message, accountAddress));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, messageToSign);

        UniversalSigValidator universalSigValidator = new UniversalSigValidator();

        bytes memory sig = abi.encodePacked(r, s, v);

        assertTrue(universalSigValidator.isValidSig(accountAddress, message, sig));
    }

    function testUnclaimedAccountSignatureVerification_InvalidWhen_DifferentAccount() public {
        uint256 salt = 1;
        address accountAddress = registry.createAccount(salt);
        bytes32 message = keccak256("Arbitrary message");
        bytes32 messageToSign = keccak256(abi.encodePacked(message, registry.account(2)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, messageToSign);

        UniversalSigValidator universalSigValidator = new UniversalSigValidator();

        bytes memory sig = abi.encodePacked(r, s, v);

        assertFalse(universalSigValidator.isValidSig(accountAddress, message, sig));
    }
}
