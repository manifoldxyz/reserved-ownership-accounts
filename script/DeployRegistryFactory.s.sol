// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";

import {AccountRegistryFactory} from "../src/AccountRegistryFactory.sol";

contract DeployRegistry is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("TESTNET_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        new AccountRegistryFactory{
            salt: 0x1337133713371337133713371337133713371337133713371337133713371337
        }();

        vm.stopBroadcast();
    }
}
