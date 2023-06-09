// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

library Address {
    function isDeployed(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}
