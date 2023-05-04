// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {AccountRegistryImplementation} from "../../../../src/examples/registry/AccountRegistryImplementation.sol";
import {AccountRegistryFactory} from "../../../../src/examples/factory/AccountRegistryFactory.sol";
import {ERC1967AccountProxy} from "../../../../src/examples/account/ERC1967AccountProxy.sol";
import {ERC1967AccountImplementation} from "../../../../src/examples/account/ERC1967AccountImplementation.sol";

contract AccountRegistryFactoryTest is Test {
    AccountRegistryImplementation internal registry;
    AccountRegistryFactory internal factory;
    ERC1967AccountImplementation internal implementation;
    ERC1967AccountProxy internal proxy;
    address internal deployer;
    address internal signer;
    uint256 internal signerPrivateKey;
    address internal accountOwner;

    function setUp() public {
        signerPrivateKey = 0x1337;
        signer = vm.addr(signerPrivateKey);
        deployer = vm.addr(1);
        accountOwner = vm.addr(2);
        factory = new AccountRegistryFactory();
        implementation = new ERC1967AccountImplementation();
        proxy = new ERC1967AccountProxy();
        registry = new AccountRegistryImplementation();
        vm.etch(0x076B08EDE2B28fab0c1886F029cD6d02C8fF0E94, address(registry).code);
    }

    function testCreateRegistryAndAccount() public {
        uint96 index = 1;

        vm.startPrank(deployer);
        AccountRegistryImplementation newRegistry = AccountRegistryImplementation(
            payable(factory.createRegistry(address(proxy), index))
        );
        newRegistry.setSigner(signer);
        vm.stopPrank();

        uint256 salt = 1;
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);

        vm.prank(accountOwner);

        ERC1967AccountImplementation account = ERC1967AccountImplementation(
            payable(
                newRegistry.assignAccount(
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
