// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {AccountUpgradeable} from "../../src/AccountUpgradeable.sol";

contract AccountTest is Test {
    AccountUpgradeable internal account;
    address internal accountOwner;

    function setUp() public {
        accountOwner = vm.addr(1);
        account = new AccountUpgradeable();
        account.initialize(accountOwner);
    }

    function testOwner() public {
        assertEq(account.owner(), accountOwner);
    }

    function testSetOwner() public {
        address newOwner = vm.addr(2);

        vm.prank(accountOwner);

        account.setOwner(newOwner);

        assertEq(account.owner(), newOwner);
    }

    function testSetOwner_RevertWhen_SenderNotOwner() public {
        address newOwner = vm.addr(2);

        vm.prank(newOwner);
        vm.expectRevert("Caller is not owner");

        account.setOwner(newOwner);
    }

    function testInitialize_RevertWhen_AlreadyInitialized() public {
        vm.prank(accountOwner);
        vm.expectRevert("Already initialized");

        account.initialize(accountOwner);
    }

    function testExecuteCall() public {
        vm.deal(address(account), 1 ether);
        vm.prank(accountOwner);

        account.executeCall(payable(accountOwner), 0.5 ether, "");

        assertEq(address(account).balance, 0.5 ether);
        assertEq(accountOwner.balance, 0.5 ether);
    }

    function testExecuteCall_RevertWhen_SenderNotOwner() public {
        vm.deal(address(account), 1 ether);
        vm.prank(vm.addr(2));
        vm.expectRevert("Caller is not owner");

        account.executeCall(payable(accountOwner), 0.5 ether, "");
    }
}
