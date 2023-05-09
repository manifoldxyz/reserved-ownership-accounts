// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

interface IAccountRegistryFactory {
    event AccountRegistryCreated(address registry, address accountImplementation, uint96 index);

    function createRegistry(
        uint96 index,
        address accountImplementation,
        bytes calldata accountInitData
    ) external returns (address);

    function registry(address deployer, uint96 index) external view returns (address);
}
