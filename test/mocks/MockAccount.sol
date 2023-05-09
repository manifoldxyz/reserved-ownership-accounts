// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

import {IERC165} from "openzeppelin/utils/introspection/IERC165.sol";

import {IERC1967Account} from "../../src/examples/account/IERC1967Account.sol";

contract MockAccount is IERC1967Account, IERC165 {
    bool private _initialized;

    receive() external payable {}

    function initialize(bool val) external {
        if (!val) {
            revert("disabled");
        }
        _initialized = val;
    }

    function executeCall(address, uint256, bytes calldata) external payable returns (bytes memory) {
        revert("disabled");
    }

    function owner() public pure returns (address) {
        revert("disabled");
    }

    function transferOwnership(address) external pure {
        revert("disabled");
    }

    function supportsInterface(bytes4 interfaceId) public view returns (bool) {
        if (interfaceId == 0xffffffff) return false;
        return _initialized;
    }
}
