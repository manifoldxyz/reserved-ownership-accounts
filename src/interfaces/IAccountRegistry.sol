// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IAccountRegistry {
    struct AuthorizationParams {
        uint256 expiration;
        bytes32 message;
        bytes signature;
    }

    struct Signer {
        address account;
        bool isContract;
    }

    event AccountCreated(address account, address implementation, bytes32 salt);

    function createAccount(
        bytes32 salt,
        AuthorizationParams calldata auth,
        bytes calldata initData
    ) external returns (address);

    function account(bytes32 salt) external view returns (address);

    function setSigner(address newSigner) external;
}
