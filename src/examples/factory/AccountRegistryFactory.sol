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

    address private immutable registryImplementation = 0x076B08EDE2B28fab0c1886F029cD6d02C8fF0E94;

    function createRegistry(
        address implementation,
        address accountImplementation,
        uint96 index
    ) external returns (address) {
        bytes32 salt = _getSalt(msg.sender, index);
        bytes memory code = ERC1167ProxyBytecode.createCode(registryImplementation);
        address _registry = Create2.computeAddress(salt, keccak256(code));

        if (_registry.isDeployed()) return _registry;

        _registry = Create2.deploy(0, salt, code);

        (bool success, ) = _registry.call(
            abi.encodeWithSignature(
                "initialize(address,address,address)",
                implementation,
                accountImplementation,
                msg.sender
            )
        );
        if (!success) revert InitializationFailed();

        emit AccountRegistryCreated(_registry, implementation, index);

        return _registry;
    }

    function registry(address deployer, uint96 index) external view override returns (address) {
        bytes32 salt = _getSalt(deployer, index);
        bytes memory code = ERC1167ProxyBytecode.createCode(registryImplementation);
        return Create2.computeAddress(salt, keccak256(code));
    }

    function _getSalt(address deployer, uint96 index) private pure returns (bytes32) {
        return bytes32(abi.encodePacked(deployer, index));
    }
}
