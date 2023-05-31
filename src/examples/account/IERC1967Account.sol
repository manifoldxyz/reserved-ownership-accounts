// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

interface IERC1967Account {
    event TransactionExecuted(address indexed target, uint256 indexed value, bytes data);

    struct CallParams {
        address to;
        uint256 value;
        bytes data;
    }

    receive() external payable;

    function executeCall(
        address to,
        uint256 value,
        bytes calldata data
    ) external payable returns (bytes memory);

    function batchExecuteCall(
        CallParams[] calldata callParams
    ) external payable returns (bytes[] memory);
}
