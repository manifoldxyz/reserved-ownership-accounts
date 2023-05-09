// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967AccountProxy} from "../../../../src/examples/account/ERC1967AccountProxy.sol";
import {ERC1967AccountImplementation} from "../../../../src/examples/account/ERC1967AccountImplementation.sol";

contract ExampleAccountProxyTest is Test {
    ERC1967AccountImplementation internal accountImplementation;
    ERC1967AccountProxy internal accountImplementationProxy;
    address internal accountOwner;
    bytes internal data;

    function setUp() public {
        accountOwner = vm.addr(1);
        accountImplementation = new ERC1967AccountImplementation();
        accountImplementationProxy = new ERC1967AccountProxy();
        data = abi.encodeWithSignature("initialize()");
        vm.prank(accountOwner);
        accountImplementationProxy.initialize(address(accountImplementation), data);
    }

    function testOwner() public {
        assertEq(
            ERC1967AccountImplementation(payable(accountImplementationProxy)).owner(),
            accountOwner
        );
    }

    function testTransferOwnership() public {
        address newOwner = vm.addr(2);

        vm.prank(accountOwner);

        ERC1967AccountImplementation(payable(accountImplementationProxy)).transferOwnership(
            newOwner
        );

        assertEq(
            ERC1967AccountImplementation(payable(accountImplementationProxy)).owner(),
            newOwner
        );
    }

    function testTransferOwnership_RevertWhen_SenderNotOwner() public {
        address newOwner = vm.addr(2);

        vm.prank(newOwner);
        vm.expectRevert("Ownable: caller is not the owner");

        ERC1967AccountImplementation(payable(accountImplementationProxy)).transferOwnership(
            newOwner
        );
    }

    function testInitialize_RevertWhen_AlreadyInitialized() public {
        vm.prank(accountOwner);
        vm.expectRevert("Already initialized");

        accountImplementationProxy.initialize(address(accountImplementation), data);
    }

    function testExecuteCall() public {
        vm.deal(address(accountImplementationProxy), 1 ether);
        vm.prank(accountOwner);

        ERC1967AccountImplementation(payable(accountImplementationProxy)).executeCall(
            payable(accountOwner),
            0.5 ether,
            ""
        );

        assertEq(address(accountImplementationProxy).balance, 0.5 ether);
        assertEq(accountOwner.balance, 0.5 ether);
    }

    function testExecuteCall_RevertWhen_SenderNotOwner() public {
        vm.deal(address(accountImplementationProxy), 1 ether);
        vm.prank(vm.addr(2));
        vm.expectRevert("Ownable: caller is not the owner");

        ERC1967AccountImplementation(payable(accountImplementationProxy)).executeCall(
            payable(accountOwner),
            0.5 ether,
            ""
        );
    }

    function testUpgrade() public {
        address newImplementation = address(new ERC1967AccountImplementation());
        vm.prank(accountOwner);

        accountImplementationProxy.upgrade(newImplementation);

        assertEq(accountImplementationProxy.implementation(), address(newImplementation));
    }

    function testUpgrade_RevertWhen_SenderNotOwner() public {
        address newImplementation = address(new ERC1967AccountImplementation());
        vm.prank(vm.addr(2));
        vm.expectRevert("Ownable: caller is not the owner");

        accountImplementationProxy.upgrade(newImplementation);
    }
}
