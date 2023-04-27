// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {AccountProxy} from "../../src/AccountProxy.sol";
import {AccountUpgradeable} from "../../src/AccountUpgradeable.sol";

contract AccountUpgradeableTest is Test {
    AccountUpgradeable internal accountUpgradeable;
    AccountProxy internal accountProxy;
    address internal accountOwner;
    bytes internal data;

    function setUp() public {
        accountOwner = vm.addr(1);
        accountUpgradeable = new AccountUpgradeable();
        accountProxy = new AccountProxy();
        data = abi.encodeWithSignature("initialize(address)", accountOwner);
        vm.prank(accountOwner);
        accountProxy.initialize(address(accountUpgradeable), data);
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

        accountProxy.initialize(address(accountUpgradeable), data);
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

        accountProxy.upgrade(newImplementation);

        assertEq(accountProxy.implementation(), address(newImplementation));
    }

    function testUpgrade_RevertWhen_SenderNotOwner() public {
        address newImplementation = address(new AccountUpgradeable());
        vm.prank(vm.addr(2));
        vm.expectRevert("Caller is not owner");

        accountProxy.upgrade(newImplementation);
    }
}
