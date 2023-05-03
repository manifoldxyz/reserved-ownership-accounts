// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";

import {AccountRegistryImplementation} from "../../../src/examples/registry/AccountRegistryImplementation.sol";

contract DeployRegistry is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        new AccountRegistryImplementation{
            salt: 0x7331733173317331733173317331733173317331733173317331733173317331
        }(address(0));

        vm.stopBroadcast();
    }
}
