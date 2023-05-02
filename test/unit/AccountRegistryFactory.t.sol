// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {AccountRegistryFactory} from "../../src/AccountRegistryFactory.sol";
import {AccountRegistry} from "../../src/AccountRegistry.sol";

contract AccountRegistryFactoryTest is Test {
    AccountRegistryFactory internal factory;
    AccountRegistry internal registryImplementation;
    address internal deployer;

    function setUp() public {
        deployer = vm.addr(1);
        factory = new AccountRegistryFactory();
        vm.prank(0xb58164C376eb9D920E83162E8dcD3dE122bA8a34);
        registryImplementation = new AccountRegistry{
            salt: 0x7331733173317331733173317331733173317331733173317331733173317331
        }(address(0));
    }

    function testRegistry() public {
        uint96 index = 1;

        address registry = factory.registry(deployer, index);

        assertNotEq(registry, address(0));
    }

    function testCreateRegistry() public {
        uint96 index = 1;

        address registry = factory.createRegistry(deployer, index);

        assertNotEq(registry, address(0));
    }

    function test_AddressesMatch() public {
        uint96 index = 1;

        address registry = factory.registry(deployer, index);

        vm.prank(deployer);

        address created = factory.createRegistry(address(registryImplementation), index);

        assertEq(created, registry);
    }

    function test_DifferentAddresses_DifferentDeployers() public {
        uint96 index = 1;

        address registry1 = factory.registry(deployer, index);
        address registry2 = factory.registry(vm.addr(2), index);

        assertNotEq(registry1, registry2);
    }

    function test_DifferentAddresses_DifferentIndexes() public {
        uint96 index = 1;

        address registry1 = factory.registry(deployer, index);
        address registry2 = factory.registry(deployer, index + 1);

        assertNotEq(registry1, registry2);
    }
}
