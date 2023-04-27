// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import {AccountUpgradeable} from "../../src/AccountUpgradeable.sol";

contract AccountUpgradeableTest is Test {
    AccountUpgradeable internal accountUpgradeable;
    ERC1967Proxy internal accountProxy;
    address internal accountOwner;
    bytes internal data;

    function setUp() public {
        accountOwner = vm.addr(1);
        accountUpgradeable = new AccountUpgradeable();
        vm.prank(accountOwner);
        accountProxy = new ERC1967Proxy(
            address(accountUpgradeable),
            abi.encodeWithSignature("initialize()")
        );
    }

    function testOwner() public {
        assertEq(AccountUpgradeable(payable(accountProxy)).owner(), accountOwner);
    }

    function testSetOwner() public {
        address newOwner = vm.addr(2);

        vm.prank(accountOwner);

        AccountUpgradeable(payable(accountProxy)).setOwner(newOwner);

        assertEq(AccountUpgradeable(payable(accountProxy)).owner(), newOwner);
    }

    function testSetOwner_RevertWhen_SenderNotOwner() public {
        address newOwner = vm.addr(2);

        vm.prank(newOwner);
        vm.expectRevert("Caller is not owner");

        AccountUpgradeable(payable(accountProxy)).setOwner(newOwner);
    }

    function testInitialize_RevertWhen_AlreadyInitialized() public {
        vm.prank(accountOwner);
        vm.expectRevert("Already initialized");

        AccountUpgradeable(payable(accountProxy)).initialize();
    }

    function testExecuteCall() public {
        vm.deal(address(accountProxy), 1 ether);
        vm.prank(accountOwner);

        AccountUpgradeable(payable(accountProxy)).executeCall(payable(accountOwner), 0.5 ether, "");

        assertEq(address(accountProxy).balance, 0.5 ether);
        assertEq(accountOwner.balance, 0.5 ether);
    }

    function testExecuteCall_RevertWhen_SenderNotOwner() public {
        vm.deal(address(accountProxy), 1 ether);
        vm.prank(vm.addr(2));
        vm.expectRevert("Caller is not owner");

        AccountUpgradeable(payable(accountProxy)).executeCall(payable(accountOwner), 0.5 ether, "");
    }

    function testUpgrade() public {
        address newImplementation = address(new AccountUpgradeable());
        vm.prank(accountOwner);

        AccountUpgradeable(payable(accountProxy)).upgrade(newImplementation);
        address implementation = address(
            uint160(
                uint256(
                    vm.load(
                        address(accountProxy),
                        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
                    )
                )
            )
        );

        assertEq(implementation, address(newImplementation));
    }

    function testUpgrade_RevertWhen_SenderNotOwner() public {
        address newImplementation = address(new AccountUpgradeable());
        vm.prank(vm.addr(2));
        vm.expectRevert("Caller is not owner");

        AccountUpgradeable(payable(accountProxy)).upgrade(newImplementation);
    }
}
