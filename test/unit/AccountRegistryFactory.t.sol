// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {AccountRegistryFactory} from "../../src/AccountRegistryFactory.sol";
import {AccountRegistry} from "../../src/AccountRegistry.sol";

contract AccountRegistryFactoryTest is Test {
    AccountRegistryFactory internal factory;
    AccountRegistry internal implementation;
    address internal deployer;

    function setUp() public {
        deployer = vm.addr(0x1337);
        factory = new AccountRegistryFactory();
        implementation = new AccountRegistry();
    }

    function testRegistry() public {
        uint256 index = 1;

        address registry = factory.registry(address(implementation), deployer, index);

        assertNotEq(registry, address(0));
    }

    function testCreateRegistry() public {
        uint256 index = 1;

        address registry = factory.createRegistry(address(implementation), index);

        assertNotEq(registry, address(0));
    }

    function test_AddressesMatch() public {
        uint256 index = 1;

        address registry = factory.registry(address(implementation), deployer, index);

        vm.prank(deployer);

        address created = factory.createRegistry(address(implementation), index);

        assertEq(created, registry);
    }

    function test_DifferentAddresses_DifferentDeployers() public {
        uint256 index = 1;

        address registry1 = factory.registry(address(implementation), deployer, index);
        address registry2 = factory.registry(address(implementation), vm.addr(2), index);

        assertNotEq(registry1, registry2);
    }

    function test_DifferentAddresses_DifferentIndexes() public {
        uint256 index = 1;

        address registry1 = factory.registry(address(implementation), deployer, index);
        address registry2 = factory.registry(address(implementation), deployer, index + 1);

        assertNotEq(registry1, registry2);
    }
}
