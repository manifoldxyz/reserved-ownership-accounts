// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967AccountProxy} from "../../../../src/examples/account/ERC1967AccountProxy.sol";
import {ERC1967AccountImplementation} from "../../../../src/examples/account/ERC1967AccountImplementation.sol";

contract ExampleAccountProxyTest is Test {
    ERC1967AccountImplementation internal implementation;
    ERC1967AccountProxy internal proxy;
    address internal accountOwner;
    bytes internal data;

    function setUp() public {
        accountOwner = vm.addr(1);
        implementation = new ERC1967AccountImplementation();
        proxy = new ERC1967AccountProxy();
        data = abi.encodeWithSignature("initialize(address)", accountOwner);
        vm.prank(accountOwner);
        proxy.initialize(address(implementation), data);
    }

    function testOwner() public {
        assertEq(ERC1967AccountImplementation(payable(proxy)).owner(), accountOwner);
    }

    function testSetOwner() public {
        address newOwner = vm.addr(2);

        vm.prank(accountOwner);

        ERC1967AccountImplementation(payable(proxy)).setOwner(newOwner);

        assertEq(ERC1967AccountImplementation(payable(proxy)).owner(), newOwner);
    }

    function testSetOwner_RevertWhen_SenderNotOwner() public {
        address newOwner = vm.addr(2);

        vm.prank(newOwner);
        vm.expectRevert("Caller is not owner");

        ERC1967AccountImplementation(payable(proxy)).setOwner(newOwner);
    }

    function testInitialize_RevertWhen_AlreadyInitialized() public {
        vm.prank(accountOwner);
        vm.expectRevert("Already initialized");

        proxy.initialize(address(implementation), data);
    }

    function testExecuteCall() public {
        vm.deal(address(proxy), 1 ether);
        vm.prank(accountOwner);

        ERC1967AccountImplementation(payable(proxy)).executeCall(
            payable(accountOwner),
            0.5 ether,
            ""
        );

        assertEq(address(proxy).balance, 0.5 ether);
        assertEq(accountOwner.balance, 0.5 ether);
    }

    function testExecuteCall_RevertWhen_SenderNotOwner() public {
        vm.deal(address(proxy), 1 ether);
        vm.prank(vm.addr(2));
        vm.expectRevert("Caller is not owner");

        ERC1967AccountImplementation(payable(proxy)).executeCall(
            payable(accountOwner),
            0.5 ether,
            ""
        );
    }

    function testUpgrade() public {
        address newImplementation = address(new ERC1967AccountImplementation());
        vm.prank(accountOwner);

        proxy.upgrade(newImplementation);

        assertEq(proxy.implementation(), address(newImplementation));
    }

    function testUpgrade_RevertWhen_SenderNotOwner() public {
        address newImplementation = address(new ERC1967AccountImplementation());
        vm.prank(vm.addr(2));
        vm.expectRevert("Caller is not owner");

        proxy.upgrade(newImplementation);
    }
}
