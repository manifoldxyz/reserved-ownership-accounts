// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {console} from "forge-std/console.sol";
import {Script} from "forge-std/Script.sol";

import {AccountRegistry} from "../src/AccountRegistry.sol";

contract ComputeRegistryAddress is Script {
    function run() external {
        vm.prank(0xb58164C376eb9D920E83162E8dcD3dE122bA8a34);

        AccountRegistry registry = new AccountRegistry{
            salt: 0x7331733173317331733173317331733173317331733173317331733173317331
        }(address(0));

        console.log("Registry address: %s", address(registry));
    }
}
