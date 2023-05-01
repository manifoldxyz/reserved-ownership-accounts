// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @author: manifold.xyz

import {Create2} from "openzeppelin/utils/Create2.sol";

import {Address} from "./lib/Address.sol";
import {IAccountRegistryFactory} from "./interfaces/IAccountRegistryFactory.sol";
import {ERC1167ProxyBytecode} from "./lib/ERC1167ProxyBytecode.sol";

contract AccountRegistryFactory is IAccountRegistryFactory {
    using Address for address;

    function createRegistry(address implementation, uint256 index) external returns (address) {
        bytes memory code = ERC1167ProxyBytecode.createCode(implementation, msg.sender, index);
        bytes32 salt = bytes32(index);

        address _registry = Create2.computeAddress(salt, keccak256(code));

        if (_registry.isDeployed()) return _registry;

        _registry = Create2.deploy(0, salt, code);

        emit AccountRegistryCreated(_registry, implementation, index);

        return _registry;
    }

    function registry(
        address implementation,
        address deployer,
        uint256 index
    ) external view override returns (address) {
        bytes memory code = ERC1167ProxyBytecode.createCode(implementation, deployer, index);
        return Create2.computeAddress(bytes32(index), keccak256(code));
    }
}
