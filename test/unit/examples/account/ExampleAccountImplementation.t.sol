// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967AccountImplementation} from "../../../../src/examples/account/ERC1967AccountImplementation.sol";
import {Clones} from "openzeppelin/proxy/Clones.sol";

contract ExampleAccountImplementationTest is Test {
    ERC1967AccountImplementation internal accountImplementation;
    address internal accountOwner;

    function setUp() public {
        accountOwner = vm.addr(1);
        accountImplementation = ERC1967AccountImplementation(
            payable(Clones.clone(address(new ERC1967AccountImplementation())))
        );
        vm.prank(accountOwner);
        accountImplementation.initialize();
    }

    function testOwner() public {
        assertEq(accountImplementation.owner(), accountOwner);
    }

    function testTransferOwnership() public {
        address newOwner = vm.addr(2);

        vm.prank(accountOwner);

        accountImplementation.transferOwnership(newOwner);

        assertEq(accountImplementation.owner(), newOwner);
    }

    function testTransferOwnership_RevertWhen_SenderNotOwner() public {
        address newOwner = vm.addr(2);

        vm.prank(newOwner);
        vm.expectRevert("Ownable: caller is not the owner");

        accountImplementation.transferOwnership(newOwner);
    }

    function testInitialize_RevertWhen_AlreadyInitialized() public {
        vm.prank(accountOwner);
        vm.expectRevert("Initializable: contract is already initialized");

        accountImplementation.initialize();
    }

    function testExecuteCall() public {
        vm.deal(address(accountImplementation), 1 ether);
        vm.prank(accountOwner);

        accountImplementation.executeCall(payable(accountOwner), 0.5 ether, "");

        assertEq(address(accountImplementation).balance, 0.5 ether);
        assertEq(accountOwner.balance, 0.5 ether);
    }

    function testExecuteCall_RevertWhen_SenderNotOwner() public {
        vm.deal(address(accountImplementation), 1 ether);
        vm.prank(vm.addr(2));
        vm.expectRevert("Ownable: caller is not the owner");

        accountImplementation.executeCall(payable(accountOwner), 0.5 ether, "");
    }
}
