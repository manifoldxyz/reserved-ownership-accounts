// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";

import {ERC1967AccountProxy} from "../../../src/examples/account/ERC1967AccountProxy.sol";

contract DeployAccountProxy is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        new ERC1967AccountProxy{
            salt: 0x6981698169816981698169816981698169816981698169816981698169816981
        }();

        vm.stopBroadcast();
    }
}
