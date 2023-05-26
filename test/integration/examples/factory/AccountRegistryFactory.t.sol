// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {AccountRegistryImplementation} from "../../../../src/examples/registry/AccountRegistryImplementation.sol";
import {AccountRegistryFactory} from "../../../../src/examples/factory/AccountRegistryFactory.sol";
import {ERC1967AccountProxy} from "../../../../src/examples/account/ERC1967AccountProxy.sol";
import {ERC1967AccountImplementation} from "../../../../src/examples/account/ERC1967AccountImplementation.sol";

contract AccountRegistryFactoryTest is Test {
    AccountRegistryImplementation internal registry;
    AccountRegistryFactory internal factory;
    ERC1967AccountImplementation internal accountImplementation;
    ERC1967AccountProxy internal accountImplementationProxy;
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
        accountImplementation = new ERC1967AccountImplementation();
        accountImplementationProxy = new ERC1967AccountProxy();
        registry = new AccountRegistryImplementation();
        vm.etch(0x804b223Abc0b810B3FAD2980d17E31DAb3A4E9DB, address(registry).code);
    }

    function testCreateRegistryAndAccount() public {
        uint96 index = 1;

        vm.startPrank(deployer);
        AccountRegistryImplementation newRegistry = AccountRegistryImplementation(
            payable(
                factory.createRegistry(
                    index,
                    address(accountImplementationProxy),
                    abi.encodeWithSignature(
                        "initialize(address,bytes)",
                        accountImplementation,
                        abi.encodeWithSignature("initialize()")
                    )
                )
            )
        );
        newRegistry.updateSigner(signer);
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
                newRegistry.claimAccount(
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
}
