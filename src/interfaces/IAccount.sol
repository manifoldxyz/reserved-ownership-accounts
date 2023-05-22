// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

import {IERC1271} from "openzeppelin/interfaces/IERC1271.sol";

interface IAccount is IERC1271 {
    /**
     * @dev Sets the owner of the Account Instance.
     *
     * Only callable by the current owner of the instance, or by the registry if the Account
     * Instance has not yet been claimed.
     *
     * @param owner      - The new owner of the Account Instance
     */
    function setOwner(address owner) external;
}
