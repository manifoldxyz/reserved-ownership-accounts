// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

import {console} from "forge-std/console.sol";
import {Script} from "forge-std/Script.sol";

import {AccountRegistryImplementation} from "../../src/examples/registry/AccountRegistryImplementation.sol";
import {ERC1967AccountImplementation} from "../../src/examples/account/ERC1967AccountImplementation.sol";
import {ERC1967AccountProxy} from "../../src/examples/account/ERC1967AccountProxy.sol";
import {AccountRegistryFactory} from "../../src/examples/factory/AccountRegistryFactory.sol";

contract ComputeRegistryAddress is Script {
    function run() external {
        vm.startBroadcast(0x33fF22df92952663DC29ff4Fbc27cd07fbB42e7c);

        AccountRegistryImplementation registry = new AccountRegistryImplementation{
            salt: 0x7331733173317331733173317331733173317331733173317331733173317331
        }();
        ERC1967AccountImplementation accountImplementation = new ERC1967AccountImplementation{
            salt: 0x1337133713371337133713371337133713371337133713371337133713371337
        }();
        ERC1967AccountProxy accountProxy = new ERC1967AccountProxy{
            salt: 0x1337133713371337133713371337133713371337133713371337133713371337
        }();
        AccountRegistryFactory registryFactory = new AccountRegistryFactory{
            salt: 0x1337133713371337133713371337133713371337133713371337133713371337
        }();

        vm.stopBroadcast();

        console.log("Registry implementation address: %s", address(registry));
        console.log("Account implementation address: %s", address(accountImplementation));
        console.log("Account proxy address: %s", address(accountProxy));
        console.log("Registry factory address: %s", address(registryFactory));
    }
}
