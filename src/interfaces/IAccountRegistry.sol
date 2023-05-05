// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IAccountRegistry {
    /**
     * @dev Registry instances emit the AccountCreated event upon successful account creation
     */
    event AccountCreated(address account, address implementation, uint256 salt);

    /**
     * @dev Registry instances emit the AccountAssigned event upon successful account assignment
     */
    event AccountAssigned(address account, address owner);

    /**
     * @dev Creates a smart contract account.
     *
     * If account has already been created, returns the account address without calling create2.
     *
     * @param salt       - The identifying salt for which the user wishes to deploy an Account Instance
     *
     * Emits AccountCreated event
     * @return the address for which the Account Instance was created
     */
    function createAccount(uint256 salt) external returns (address);

    /**
     * @dev Assigns a smart contract account to a given owner.
     *
     * If the account has not already been created, the account will be created first using `createAccount`
     *
     * @param owner      - The initial owner of the new Account Instance
     * @param salt       - The identifying salt for which the user wishes to deploy an Account Instance
     * @param expiration - If expiration > 0, represents expiration time for the signature.  Otherwise
     *                     signature does not expire.
     * @param message    - The keccak256 message which validates the owner, salt, expiration
     * @param signature  - The signature which validates the owner, salt, expiration
     *
     * Emits AccountAssigned event
     * @return the address to which the Account Instance was assigned
     */
    function assignAccount(
        address owner,
        uint256 salt,
        uint256 expiration,
        bytes32 message,
        bytes calldata signature
    ) external returns (address);

    /**
     * @dev Returns the computed address of a smart contract account for a given identifying salt
     *
     * @return the computed address of the account
     */
    function account(uint256 salt) external view returns (address);

    /**
     * @dev Fallback signature verifiaction for non-initialized accounts
     */
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4);
}
