// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967AccountImplementation} from "../../../../src/examples/account/ERC1967AccountImplementation.sol";
import {Clones} from "openzeppelin/proxy/Clones.sol";

contract ExampleAccountImplementationTest is Test {
    ERC1967AccountImplementation internal implementation;
    address internal accountOwner;

    function setUp() public {
        accountOwner = vm.addr(1);
        implementation = ERC1967AccountImplementation(
            payable(Clones.clone(address(new ERC1967AccountImplementation())))
        );
        implementation.initialize(accountOwner);
    }

    function testOwner() public {
        assertEq(implementation.owner(), accountOwner);
    }

    function testTransferOwnership() public {
        address newOwner = vm.addr(2);

        vm.prank(accountOwner);

        implementation.transferOwnership(newOwner);

        assertEq(implementation.owner(), newOwner);
    }

    function testTransferOwnership_RevertWhen_SenderNotOwner() public {
        address newOwner = vm.addr(2);

        vm.prank(newOwner);
        vm.expectRevert("Ownable: caller is not the owner");

        implementation.transferOwnership(newOwner);
    }

    function testInitialize_RevertWhen_AlreadyInitialized() public {
        vm.prank(accountOwner);
        vm.expectRevert("Initializable: contract is already initialized");

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
        vm.expectRevert("Ownable: caller is not the owner");

        implementation.executeCall(payable(accountOwner), 0.5 ether, "");
    }
}
