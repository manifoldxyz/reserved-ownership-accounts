// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {AccountRegistryImplementation} from "../../../../src/examples/registry/AccountRegistryImplementation.sol";
import {ERC1967AccountProxy} from "../../../../src/examples/account/ERC1967AccountProxy.sol";
import {ERC1967AccountImplementation} from "../../../../src/examples/account/ERC1967AccountImplementation.sol";
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
        registry.initialize(address(proxy), address(this));
        registry.setSigner(signer);
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
                registry.assignAccount(
                    accountOwner,
                    salt,
                    expiration,
                    message,
                    abi.encodePacked(r, s, v),
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
