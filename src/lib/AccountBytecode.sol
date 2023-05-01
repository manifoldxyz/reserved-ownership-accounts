// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

library AccountBytecode {

    function createCode(
        address implementation
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                hex"3d608e80600a3d3981f3363d3d373d3d3d363d73",
                implementation,
                hex"5af43d82803e903d91602b57fd5bf300"
            );
    }
}
