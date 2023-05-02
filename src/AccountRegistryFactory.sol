// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @author: manifold.xyz

import {Create2} from "openzeppelin/utils/Create2.sol";

import {Address} from "./lib/Address.sol";
import {IAccountRegistryFactory} from "./interfaces/IAccountRegistryFactory.sol";
import {ERC1167ProxyBytecode} from "./lib/ERC1167ProxyBytecode.sol";

contract AccountRegistryFactory is IAccountRegistryFactory {
    using Address for address;

    error InitializationFailed();

    address private immutable registryImplementation = 0x5bB5507be35BA3109E8556bF47321aF3D1f144cf;

    function createRegistry(address implementation, uint256 index) external returns (address) {
        bytes32 salt = bytes32(index);
        bytes memory code = ERC1167ProxyBytecode.createCode(
            registryImplementation,
            msg.sender,
            index
        );
        address _registry = Create2.computeAddress(salt, keccak256(code));

        if (_registry.isDeployed()) return _registry;

        _registry = Create2.deploy(0, salt, code);

        (bool success, ) = _registry.call(
            abi.encodeWithSignature("initialize(address,address)", implementation, msg.sender)
        );
        if (!success) revert InitializationFailed();

        emit AccountRegistryCreated(_registry, implementation, index);

        return _registry;
    }

    function registry(address deployer, uint256 index) external view override returns (address) {
        bytes memory code = ERC1167ProxyBytecode.createCode(
            registryImplementation,
            deployer,
            index
        );
        return Create2.computeAddress(bytes32(index), keccak256(code));
    }
}
