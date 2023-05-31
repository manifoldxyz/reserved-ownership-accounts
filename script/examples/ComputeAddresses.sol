// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

import {console} from "forge-std/console.sol";
import {Script} from "forge-std/Script.sol";

import {AccountRegistryFactory} from "../../src/examples/factory/AccountRegistryFactory.sol";
import {AccountRegistryImplementation} from "../../src/examples/registry/AccountRegistryImplementation.sol";
import {ERC1967AccountImplementation} from "../../src/examples/account/ERC1967AccountImplementation.sol";
import {ERC1967AccountProxy} from "../../src/examples/account/ERC1967AccountProxy.sol";

contract ComputeAddresses is Script {
    function run() external {
        vm.startBroadcast(0xa8863bf1c8933f649e7b03Eb72109E5E187505Ea);

        AccountRegistryFactory factory = new AccountRegistryFactory{
            salt: 0x6981698169816981698169816981698169816981698169816981698169816981
        }();
        AccountRegistryImplementation registry = new AccountRegistryImplementation{
            salt: 0x6981698169816981698169816981698169816981698169816981698169816981
        }();
        ERC1967AccountImplementation erc1967AccountImpl = new ERC1967AccountImplementation{
            salt: 0x6981698169816981698169816981698169816981698169816981698169816981
        }();
        ERC1967AccountProxy erc1967AccountProxy = new ERC1967AccountProxy{
            salt: 0x6981698169816981698169816981698169816981698169816981698169816981
        }();

        vm.stopBroadcast();

        console.log("Factory address: %s", address(factory));
        console.log("Registry address: %s", address(registry));
        console.log("ERC1967AccountImplementation address: %s", address(erc1967AccountImpl));
        console.log("ERC1967AccountProxy address: %s", address(erc1967AccountProxy));
    }
}
