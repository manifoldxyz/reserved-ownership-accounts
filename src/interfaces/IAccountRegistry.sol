// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IAccountRegistry {
    /**
     * @dev Registry instances emit the AccountCreated event upon successful account creation
     */
    event AccountCreated(
        address account,
        address implementation,
        uint256 salt
    );

    /**
     * @dev Creates a smart contract account.
     *
     * If account has already been created, returns the account address without calling create2.
     * 
     * @param salt       - The identifying salt for which the user wishes to deploy an Account Instance
     * @param expiration - If expiration > 0, represents expiration time for the signature.  Otherwise
     *                     signature does not expire.
     * @param message    - The keccak256 message which validates the ability for the msg.sender to deploy
     * @param signature  - The signature which validates the ability for the msg.sender to deploy
     * @param initData   - If initData is not empty and account has not yet been created, calls account with
     *                     provided initData after creation.
     *
     * Emits AccountCreated event
     * @return the address for which the Account Instance was created
     */ 
    function createAccount(
        uint256 salt,
        uint256 expiration,
        bytes32 message,
        bytes calldata signature,
        bytes calldata initData
    ) external returns (address);

    /**
     * @dev Returns the computed address of a smart contract account for a given identifying salt
     *
     * @return the computed address of the account
     */ 
    function account(uint256 salt) external view returns (address);
}