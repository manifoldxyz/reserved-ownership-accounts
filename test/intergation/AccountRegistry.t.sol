// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {console} from "forge-std/console.sol";
import {Test} from "forge-std/Test.sol";
import {IAccountRegistry} from "../../src/interfaces/IAccountRegistry.sol";
import {AccountRegistry} from "../../src/AccountRegistry.sol";
import {AccountProxy} from "../../src/AccountProxy.sol";
import {AccountUpgradeable} from "../../src/AccountUpgradeable.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract AccountRegistryTest is Test {
    AccountRegistry internal registry;
    AccountUpgradeable internal implementation;
    AccountProxy internal implProxy;
    address internal signer;
    uint256 internal signerPrivateKey;
    address internal accountOwner;

    function setUp() public {
        signerPrivateKey = 0x1337;
        signer = vm.addr(signerPrivateKey);
        accountOwner = vm.addr(1);
        registry = new AccountRegistry();
        registry.setSigner(signer);
        implementation = new AccountUpgradeable();
        implProxy = new AccountProxy();
    }

    function testCreateAccount() public {
        uint256 chainId = 1;
        bytes32 salt = "1";
        uint256 expiration = block.timestamp + 10000;
        bytes32 message = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n84", accountOwner, salt, expiration)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, message);
        IAccountRegistry.AuthorizationParams memory auth = IAccountRegistry.AuthorizationParams({
            expiration: expiration,
            message: message,
            signature: abi.encodePacked(r, s, v)
        });

        vm.prank(accountOwner);

        AccountUpgradeable account = AccountUpgradeable(
            payable(
                registry.createAccount(
                    address(implProxy),
                    chainId,
                    salt,
                    auth,
                    abi.encodeWithSignature(
                        "initialize(address,bytes)",
                        address(implementation),
                        abi.encodeWithSignature("initialize(address)", accountOwner)
                    )
                )
            )
        );

        assertEq(account.owner(), accountOwner);
    }
}
