// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IERC1271} from "openzeppelin/interfaces/IERC1271.sol";

contract MockSigner is IERC1271 {
    bool private _signatureValid;

    receive() external payable {}

    function mockIsValid(bool valid) external {
        _signatureValid = valid;
    }

    function isValidSignature(bytes32, bytes calldata) external view override returns (bytes4) {
        return _signatureValid ? IERC1271.isValidSignature.selector : bytes4("");
    }
}
