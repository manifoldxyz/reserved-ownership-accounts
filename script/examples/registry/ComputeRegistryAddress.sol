// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {console} from "forge-std/console.sol";
import {Script} from "forge-std/Script.sol";

import {AccountRegistryImplementation} from "../../../src/examples/registry/AccountRegistryImplementation.sol";

contract ComputeRegistryAddress is Script {
    function run() external {
        vm.prank(0xb58164C376eb9D920E83162E8dcD3dE122bA8a34);

        AccountRegistryImplementation registry = new AccountRegistryImplementation{
            salt: 0x7331733173317331733173317331733173317331733173317331733173317331
        }();

        console.log("Registry address: %s", address(registry));
    }
}
