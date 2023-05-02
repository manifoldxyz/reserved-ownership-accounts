// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {IAccountRegistry} from "../../src/interfaces/IAccountRegistry.sol";
import {AccountRegistry} from "../../src/AccountRegistry.sol";
import {AccountRegistryFactory} from "../../src/AccountRegistryFactory.sol";
import {ERC1967AccountProxy} from "../../src/examples/upgradeable/ERC1967AccountProxy.sol";
import {ERC1967AccountImplementation} from "../../src/examples/upgradeable/ERC1967AccountImplementation.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract AccountRegistryFactoryTest is Test {
    AccountRegistry internal registry;
    AccountRegistryFactory internal factory;
    ERC1967AccountImplementation internal implementation;
    ERC1967AccountProxy internal proxy;
    address internal deployer;
    address internal signer;
    uint256 internal signerPrivateKey;
    address internal accountOwner;

    function setUp() public {
        signerPrivateKey = 0x1337;
        signer = vm.addr(signerPrivateKey);
        deployer = vm.addr(1);
        accountOwner = vm.addr(2);
        factory = new AccountRegistryFactory();
        implementation = new ERC1967AccountImplementation();
        proxy = new ERC1967AccountProxy();
        vm.prank(0xb58164C376eb9D920E83162E8dcD3dE122bA8a34);
        registry = new AccountRegistry{
            salt: 0x7331733173317331733173317331733173317331733173317331733173317331
        }(address(0));
    }

    function testCreateRegistryAndAccount() public {
        uint96 index = 1;

        vm.startPrank(deployer);
        AccountRegistry newRegistry = AccountRegistry(
            payable(factory.createRegistry(address(proxy), index))
        );
        newRegistry.setSigner(signer);
        vm.stopPrank();

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

        ERC1967AccountImplementation account = ERC1967AccountImplementation(
            payable(
                newRegistry.createAccount(
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
