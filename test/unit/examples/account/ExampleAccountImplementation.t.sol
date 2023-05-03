// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967AccountImplementation} from "../../../../src/examples/account/ERC1967AccountImplementation.sol";

contract ExampleAccountImplementationTest is Test {
    ERC1967AccountImplementation internal implementation;
    address internal accountOwner;

    function setUp() public {
        accountOwner = vm.addr(1);
        implementation = new ERC1967AccountImplementation();
        implementation.initialize(accountOwner);
    }

    function testOwner() public {
        assertEq(implementation.owner(), accountOwner);
    }

    function testSetOwner() public {
        address newOwner = vm.addr(2);

        vm.prank(accountOwner);

        implementation.setOwner(newOwner);

        assertEq(implementation.owner(), newOwner);
    }

    function testSetOwner_RevertWhen_SenderNotOwner() public {
        address newOwner = vm.addr(2);

        vm.prank(newOwner);
        vm.expectRevert("Caller is not owner");

        implementation.setOwner(newOwner);
    }

    function testInitialize_RevertWhen_AlreadyInitialized() public {
        vm.prank(accountOwner);
        vm.expectRevert("Already initialized");

        implementation.initialize(accountOwner);
    }

    function testExecuteCall() public {
        vm.deal(address(implementation), 1 ether);
        vm.prank(accountOwner);

        implementation.executeCall(payable(accountOwner), 0.5 ether, "");

        assertEq(address(implementation).balance, 0.5 ether);
        assertEq(accountOwner.balance, 0.5 ether);
    }

    function testExecuteCall_RevertWhen_SenderNotOwner() public {
        vm.deal(address(implementation), 1 ether);
        vm.prank(vm.addr(2));
        vm.expectRevert("Caller is not owner");

        implementation.executeCall(payable(accountOwner), 0.5 ether, "");
    }
}
