// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

/// @author: manifold.xyz

import {Create2} from "openzeppelin/utils/Create2.sol";

import {Address} from "../../lib/Address.sol";
import {ERC1167ProxyBytecode} from "../../lib/ERC1167ProxyBytecode.sol";
import {IAccountRegistryFactory} from "./IAccountRegistryFactory.sol";

contract AccountRegistryFactory is IAccountRegistryFactory {
    using Address for address;

    error InitializationFailed();

    address private immutable _registryImplementation = 0x804b223Abc0b810B3FAD2980d17E31DAb3A4E9DB;

    function createRegistry(
        uint96 index,
        address accountImplementation,
        bytes calldata accountInitData
    ) external returns (address) {
        bytes32 salt = _getSalt(msg.sender, index);
        bytes memory code = ERC1167ProxyBytecode.createCode(_registryImplementation);
        address _registry = Create2.computeAddress(salt, keccak256(code));

        if (_registry.isDeployed()) return _registry;

        _registry = Create2.deploy(0, salt, code);

        (bool success, ) = _registry.call(
            abi.encodeWithSignature(
                "initialize(address,address,bytes)",
                msg.sender,
                accountImplementation,
                accountInitData
            )
        );
        if (!success) revert InitializationFailed();

        emit AccountRegistryCreated(_registry, accountImplementation, index);

        return _registry;
    }

    function registry(address deployer, uint96 index) external view override returns (address) {
        bytes32 salt = _getSalt(deployer, index);
        bytes memory code = ERC1167ProxyBytecode.createCode(_registryImplementation);
        return Create2.computeAddress(salt, keccak256(code));
    }

    function _getSalt(address deployer, uint96 index) private pure returns (bytes32) {
        return bytes32(abi.encodePacked(deployer, index));
    }
}
