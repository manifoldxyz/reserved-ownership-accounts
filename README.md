---
title: Deferred-Custody Smart Contract Accounts
description: A registry/factory for smart contract accounts owned by users on external services
author: Paul Sullivan (@sullivph) <paul.sullivan@manifold.xyz>, Wilkins Chung (@wwchung) <wilkins@manifold.xyz>
discussions-to: <URL>
status: Draft
type: <Standards Track, Meta, or Informational>
category: <Core, Networking, Interface, or ERC> # Only required for Standards Track. Otherwise, remove this field.
created: 2023-04-25
requires: <EIP number(s)> # Only required when you reference an EIP in the `Specification` section. Otherwise, remove this field.
---

## Abstract

The following specifies a system for external services to provide their users with smart contract accounts. With a signed message from the external service, users can deploy smart contract accounts through a registry at a deterministic address using the `create2` opcode, at which point the external service no longer maintains any control over the address.

## Motivation

It is common for web services to allow their users to hold on-chain assets via custodial wallets. These wallets are typically EOAs or omnibus contracts, with private keys or asset ownership information stored on a traditional database. This proposal outlines a solution that avoids the security concerns associated with historical approaches, and rids the need and implications of services custoding user assets

Users on external services that choose to leverage the following specification can be associated with an Ethereum address. These users can choose to attain control of said addresses at any point in time. Thus, on-chain assets can be sent to and owned by a user beforehand, therefore enabling the formation of an on-chain identity without requiring the user to interact with the underlying blockchain.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### Overview

The system for creating deferred custody accounts consists of:

1. An account registry factory contract used to create account registry instances
2. An account registry implementation proxied by account registry instances created by the factory used to create new accounts
3. An interface for the smart contract accounts created by account registry instances

External services wishing to provide their users with deferred-custody smart contract accounts MUST create a new registry through the registry factory contract. Users from a given service SHALL create accounts using the corresponding registry instance.

### Account Interface

All accounts MUST be created using a registry instance.

All account implementations MUST implement the following interface:

```solidity
interface IAccount {
  /// @dev Accounts MUST implement a `receive` function.
  ///
  /// Accounts MAY perform arbitrary logic to restrict conditions
  /// under which Ether can be received.
  receive() external payable;

  /// @dev Executes `call` on address `to`, with value `value` and calldata
  /// `data`.
  ///
  /// MUST revert and bubble up errors if call fails.
  ///
  /// By default, accounts MUST allow the current owner to execute arbitrary
  /// calls using `executeCall`.
  ///
  /// @return The result of the call
  function executeCall(
    address to,
    uint256 value,
    bytes calldata data
  ) external payable returns (bytes memory);

  /// @dev Returns the current owner of the account.
  ///
  /// @return Address of the account owner
  function owner() external view returns (address);
}
```

### Account Registry Instances

Account registry instances are deployed as an [ERC-1167](https://eips.ethereum.org/EIPS/eip-1167) proxy by the account registry factory.

The registry implementation has two main functions:

- `createAccount` - deploys a smart contract account for a user given a salt and an authroization message signed by the external service
- `account` - a read-only function that computes the smart contract account address for a user given a salt

Upon creation, registry instances are initialized with an immutable account implementation address. Calls by users to `createAccount` will deploy a new account instance that references this implementation as an [ERC-1167](https://eips.ethereum.org/EIPS/eip-1167) proxy.

Registry instances are also initialized with an owner (the deployer of the instance). The owner of the registry instance can set and update a `signer`, which can be either an EOA or a contract (per [EIP-1271](https://eips.ethereum.org/EIPS/eip-1271)) used to authorize user calls to `createAccount`.

External services SHOULD allow users to create accounts through their registry contracts by providing a signed message via the `signer`.

Signed authorization messages MUST follow the format:

```solidity
keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n84", owner, salt, expiration));
```

Where `owner` is the address that will control the new account instance, `salt` is a `bytes32` string (uniquely associated with the user), and `expiration` is a timestamp in epoch seconds that indicates when the authorization is no longer valid. Registry instances will reconstruct the message using `msg.sender` as `owner`, and the `salt` and `expiration` passed to the `createAccount` call. Registry instances will revert `createAccount` transactions if the reconstructed message does not match the signed message, or if the signature is invalid or was not signed by the registry instance's `signer`.

The registry implementation follows the interface:

```solidity
interface IAccountRegistry {
    struct AuthorizationParams {
        uint256 expiration,
        bytes32 message,
        bytes calldata signature,
    }

    struct Signer {
        address account,
        bool isContract,
    }

    /// @dev Registry instances emit the AccountCreated event upon successful account creation
    event AccountCreated(
        address account,
        address implementation,
        uint256 salt
    );

    /// @dev Creates a smart contract account.
    ///
    /// If account has already been created, returns the account address without calling create2.
    ///
    /// If initData is not empty and account has not yet been created, calls account with
    /// provided initData after creation.
    ///
    /// Emits AccountCreated event.
    ///
    /// @return the address of the account
    function createAccount(
        uint256 salt,
        AuthorizationParams calldata auth,
        bytes calldata initData
    ) external returns (address);

    /// @dev Returns the computed address of a smart contract account
    ///
    /// @return The computed address of the account
    function account(uint256 salt) external view returns (address);

    /// @dev Updates the signer used to verify auth params
    ///
    /// Only callable by the owner of the registry.
    function setSigner(address signer) external;
}
```

### Account Registry Factory

The account registry factory is a permissionless contract that will be deployed at a deterministic address on supported chains using the `create2` opcode by the deployer address `TBD` using salt `TBD`. The factory will point to the account registry implementation deployed at `TBD`. Account registry instances MUST be deployed by the account registry factory.

The factory has two functions:

- `createRegistry` - deploys an account registry instance for an external service given an account implementation address and an index
- `registry` - a read-only function that computes the registry address for a service given a deployer address and an index

Account registry instances are deployed at determinstic addresses using the `create2` opcode. The deployer address and index are concatenated and used as the salt.

The factory implements the following interface:

```solidity
interface IAccountRegistryFactory {
  /// @dev The factory emits the AccountRegistryCreated event upon successful registry instance creation
  event AccountRegistryCreated(address registry, address implementation, uint96 index);

  function createRegistry(address implementation, uint96 index) external returns (address);

  function registry(address deployer, uint96 index) external view returns (address);
}
```

## Rationale

### Service-Owned Registry Instances

While it might seem more user-friendly to implement and deploy a universal registry for deferred-custody accounts, we believe the canonical factory to multi-registry solution to be more viable. This simplifies the `signer` design that authorizes creation of new account instances on a registry, and allows services the most flexibility when assigning a salt to a given user.

### Registry Instance and Account Implementation Coupling

Since account instances are deployed as [ERC-1167](https://eips.ethereum.org/EIPS/eip-1167) proxies, the account implementation address affects the addresses of accounts deployed from a given registry instance. Requiring that registry instances be linked to a a single, immutable account implementation ensures consistency between a user's salt and linked address on a given registry instance.

This also allows services to gain the the trust of users by deploying their registries with a reference to a trusted account implementation address.

Furthermore, account implementations can be designed as upgradeable, so users are not necessarily bound to the implementation specified by the registry instance used to create their account.

## Reference Implementation

### Account Registry

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @author: manifold.xyz

import { Create2 } from "openzeppelin/utils/Create2.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { Ownable } from "openzeppelin/access/Ownable.sol";
import { Initializable } from "openzeppelin/proxy/utils/Initializable.sol";
import { IERC1271 } from "openzeppelin/interfaces/IERC1271.sol";
import { SignatureChecker } from "openzeppelin/utils/cryptography/SignatureChecker.sol";

import { Address } from "./lib/Address.sol";
import { IAccountRegistry } from "./interfaces/IAccountRegistry.sol";
import { IAccount } from "./interfaces/IAccount.sol";
import { ERC1167ProxyBytecode } from "./lib/ERC1167ProxyBytecode.sol";

contract AccountRegistry is Ownable, Initializable, IAccountRegistry {
  using Address for address;
  using ECDSA for bytes32;

  error InitializationFailed();
  error Unauthorized();

  address public implementation;
  Signer private signer;

  constructor(address implementation_) Ownable() initializer {
    implementation = implementation_;
  }

  function initialize(address implementation_, address owner) external initializer {
    implementation = implementation_;
    _transferOwnership(owner);
  }

  function createAccount(
    bytes32 salt,
    AuthorizationParams calldata auth,
    bytes calldata initData
  ) external returns (address) {
    _verify(salt, auth);
    bytes memory code = ERC1167ProxyBytecode.createCode(implementation);
    address _account = Create2.computeAddress(salt, keccak256(code));

    if (_account.isDeployed()) return _account;

    _account = Create2.deploy(0, salt, code);

    if (initData.length != 0) {
      (bool success, ) = _account.call(initData);
      if (!success) revert InitializationFailed();
    }

    emit AccountCreated(_account, implementation, salt);

    return _account;
  }

  function account(bytes32 salt) external view returns (address) {
    bytes memory code = ERC1167ProxyBytecode.createCode(implementation);
    return Create2.computeAddress(salt, keccak256(code));
  }

  function setSigner(address newSigner) external onlyOwner {
    uint32 signerSize;
    assembly {
      signerSize := extcodesize(newSigner)
    }
    signer.account = newSigner;
    signer.isContract = signerSize > 0;
  }

  function _verify(bytes32 salt, AuthorizationParams calldata auth) internal view {
    address signatureAccount;

    if (signer.isContract) {
      if (!SignatureChecker.isValidSignatureNow(signer.account, auth.message, auth.signature))
        revert Unauthorized();
    } else {
      signatureAccount = auth.message.recover(auth.signature);
    }

    bytes32 expectedMessage = keccak256(
      abi.encodePacked("\x19Ethereum Signed Message:\n84", msg.sender, salt, auth.expiration)
    );

    if (
      auth.message != expectedMessage ||
      (!signer.isContract && signatureAccount != signer.account) ||
      auth.expiration < block.timestamp
    ) revert Unauthorized();
  }
}
```

### Account Registry Factory

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @author: manifold.xyz

import { Create2 } from "openzeppelin/utils/Create2.sol";

import { Address } from "./lib/Address.sol";
import { IAccountRegistryFactory } from "./interfaces/IAccountRegistryFactory.sol";
import { ERC1167ProxyBytecode } from "./lib/ERC1167ProxyBytecode.sol";

contract AccountRegistryFactory is IAccountRegistryFactory {
  using Address for address;

  error InitializationFailed();

  address private immutable registryImplementation = 0x076B08EDE2B28fab0c1886F029cD6d02C8fF0E94;

  function createRegistry(address implementation, uint96 index) external returns (address) {
    bytes32 salt = _getSalt(msg.sender, index);
    bytes memory code = ERC1167ProxyBytecode.createCode(registryImplementation);
    address _registry = Create2.computeAddress(salt, keccak256(code));

    if (_registry.isDeployed()) return _registry;

    _registry = Create2.deploy(0, salt, code);

    (bool success, ) = _registry.call(
      abi.encodeWithSignature("initialize(address,address)", implementation, msg.sender)
    );
    if (!success) revert InitializationFailed();

    emit AccountRegistryCreated(_registry, implementation, index);

    return _registry;
  }

  function registry(address deployer, uint96 index) external view override returns (address) {
    bytes32 salt = _getSalt(deployer, index);
    bytes memory code = ERC1167ProxyBytecode.createCode(registryImplementation);
    return Create2.computeAddress(salt, keccak256(code));
  }

  function _getSalt(address deployer, uint96 index) private pure returns (bytes32) {
    return bytes32(abi.encodePacked(deployer, index));
  }
}
```

### Example Account Implementation

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.13;

/// @author: manifold.xyz

import { StorageSlot } from "openzeppelin/utils/StorageSlot.sol";

contract ERC1967AccountProxy {
  /**
   * @dev Storage slot with the address of the current implementation.
   * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
   * validated in the constructor.
   */
  bytes32 internal constant _IMPLEMENTATION_SLOT =
    0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

  constructor() {
    assert(_IMPLEMENTATION_SLOT == bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1));
  }

  modifier onlyOwner() {
    (bool success, bytes memory data) = _implementation().delegatecall(
      abi.encodeWithSignature("owner()")
    );
    require(success && abi.decode(data, (address)) == msg.sender, "Caller is not owner");
    _;
  }

  /**
   * Initializer
   */
  function initialize(
    address implementation_,
    bytes calldata initData
  ) external returns (bytes memory) {
    StorageSlot.AddressSlot storage _slot = StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT);

    require(_slot.value == address(0), "Already initialized");
    _slot.value = implementation_;

    (bool success, bytes memory data) = _implementation().delegatecall(initData);
    require(success, "Initialization failed");

    return data;
  }

  /**
   * @dev Returns the current implementation address.
   */
  function implementation() external view returns (address) {
    return _implementation();
  }

  function _implementation() internal view returns (address) {
    return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
  }

  /**
   * @dev Delegates the current call to `implementation`.
   *
   * This function does not return to its internal call site, it will return directly to the external caller.
   */
  function _delegate(address implementation_) internal virtual {
    /// @solidity memory-safe-assembly
    assembly {
      // Copy msg.data. We take full control of memory in this inline assembly
      // block because it will not return to Solidity code. We overwrite the
      // Solidity scratch pad at memory position 0.
      calldatacopy(0, 0, calldatasize())

      // Call the implementation.
      // out and outsize are 0 because we don't know the size yet.
      let result := delegatecall(gas(), implementation_, 0, calldatasize(), 0, 0)

      // Copy the returned data.
      returndatacopy(0, 0, returndatasize())

      switch result
      // delegatecall returns 0 on error.
      case 0 {
        revert(0, returndatasize())
      }
      default {
        return(0, returndatasize())
      }
    }
  }

  /**
   * @dev Upgrades the implementation.  Only the token owner can call this.
   */
  function upgrade(address implementation_) external onlyOwner {
    require(implementation_ != address(0), "Invalid implementation address");
    StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = implementation_;
  }

  /**
   * @dev Delegates the current call to the address returned by `_implementation()`.
   *
   * This function does not return to its internal call site, it will return directly to the external caller.
   */
  function _fallback() internal virtual {
    _delegate(_implementation());
  }

  /**
   * @dev Fallback function that delegates calls to the address returned by `_implementation()`. Will run if no other
   * function in the contract matches the call data.
   */
  fallback() external payable virtual {
    _fallback();
  }

  /**
   * @dev Fallback function that delegates calls to the address returned by `_implementation()`. Will run if call data
   * is empty.
   */
  receive() external payable virtual {
    _fallback();
  }
}

import { IERC1271 } from "openzeppelin/interfaces/IERC1271.sol";
import { SignatureChecker } from "openzeppelin/utils/cryptography/SignatureChecker.sol";
import { IERC165 } from "openzeppelin/utils/introspection/IERC165.sol";
import { ERC165Checker } from "openzeppelin/utils/introspection/ERC165Checker.sol";
import { IERC721 } from "openzeppelin/token/ERC721/IERC721.sol";
import { IERC721Receiver } from "openzeppelin/token/ERC721/IERC721Receiver.sol";
import { IERC1155Receiver } from "openzeppelin/token/ERC1155/IERC1155Receiver.sol";

import { IAccount } from "../../interfaces/IAccount.sol";

/**
 * @title ERC1967AccountImplementation
 * @notice A lightweight, upgradeable smart contract wallet implementation
 */
contract ERC1967AccountImplementation is
  IERC165,
  IERC721Receiver,
  IERC1155Receiver,
  IAccount,
  IERC1271
{
  address public owner;

  modifier onlyOwner() {
    require(msg.sender == owner, "Caller is not owner");
    _;
  }

  function initialize(address owner_) external {
    require(owner == address(0), "Already initialized");
    owner = owner_;
  }

  function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
    return (interfaceId == type(IAccount).interfaceId ||
      interfaceId == type(IERC1155Receiver).interfaceId ||
      interfaceId == type(IERC721Receiver).interfaceId ||
      interfaceId == type(IERC165).interfaceId);
  }

  function onERC721Received(address, address, uint256, bytes memory) public pure returns (bytes4) {
    return this.onERC721Received.selector;
  }

  function onERC1155Received(
    address,
    address,
    uint256,
    uint256,
    bytes memory
  ) public pure returns (bytes4) {
    return this.onERC1155Received.selector;
  }

  function onERC1155BatchReceived(
    address,
    address,
    uint256[] memory,
    uint256[] memory,
    bytes memory
  ) public pure returns (bytes4) {
    return this.onERC1155BatchReceived.selector;
  }

  /**
   * @dev {See IAccount-executeCall}
   */
  function executeCall(
    address _target,
    uint256 _value,
    bytes calldata _data
  ) external payable override onlyOwner returns (bytes memory _result) {
    bool success;
    // solhint-disable-next-line avoid-low-level-calls
    (success, _result) = _target.call{ value: _value }(_data);
    require(success, string(_result));
    emit TransactionExecuted(_target, _value, _data);
    return _result;
  }

  /**
   * @dev {See IAccount-setOwner}
   */
  function setOwner(address newOwner) external override onlyOwner {
    owner = newOwner;
  }

  receive() external payable {}

  function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
    bool isValid = SignatureChecker.isValidSignatureNow(owner, hash, signature);
    if (isValid) {
      return IERC1271.isValidSignature.selector;
    }

    return "";
  }
}
```

## Security Considerations

<!--
  All EIPs must contain a section that discusses the security implications/considerations relevant to the proposed change. Include information that might be important for security discussions, surfaces risks and can be used throughout the life cycle of the proposal. For example, include security-relevant design decisions, concerns, important discussions, implementation-specific guidance and pitfalls, an outline of threats and risks and how they are being addressed. EIP submissions missing the "Security Considerations" section will be rejected. An EIP cannot proceed to status "Final" without a Security Considerations discussion deemed sufficient by the reviewers.

  The current placeholder is acceptable for a draft.

  TODO: Remove this comment before submitting
-->

Needs discussion.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
