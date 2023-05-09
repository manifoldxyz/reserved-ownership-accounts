// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

interface IAccountRegistryFactory {
    event AccountRegistryCreated(address registry, address implementation, uint96 index);

    function createRegistry(
        address implementation,
        address accountImplementation,
        uint96 index
    ) external returns (address);

    function registry(address deployer, uint96 index) external view returns (address);
}
