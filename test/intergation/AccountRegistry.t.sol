// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {IAccountRegistry} from "../../src/interfaces/IAccountRegistry.sol";
import {AccountRegistry} from "../../src/AccountRegistry.sol";
import {ERC1967AccountProxy} from "../../src/examples/upgradeable/ERC1967AccountProxy.sol";
import {ERC1967AccountImplementation} from "../../src/examples/upgradeable/ERC1967AccountImplementation.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract AccountRegistryTest is Test {
    AccountRegistry internal registry;
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
        registry = new AccountRegistry(address(proxy));
        registry.setSigner(signer);
    }

    function testCreateAccount() public {
        bytes32 salt = "1";
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);
        IAccountRegistry.AuthorizationParams memory auth = IAccountRegistry.AuthorizationParams({
            expiration: expiration,
            message: message,
            signature: abi.encodePacked(r, s, v)
        });

        vm.prank(accountOwner);

        ERC1967AccountImplementation account = ERC1967AccountImplementation(
            payable(
                registry.createAccount(
                    salt,
                    auth,
                    abi.encodeWithSignature(
                        "initialize(address,bytes)",
                        address(implementation),
                        abi.encodeWithSignature("initialize(address)", accountOwner)
                    )
                )
            )
        );

        assertEq(account.owner(), accountOwner);
    }
}
