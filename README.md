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

This design allows tokens, assets, and other on-chain entities to be owned by users on external services without requiring the user to interact with the underlying blockchain in any way.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

The following is heavily based on the design for [ERC-6551](https://eips.ethereum.org/EIPS/eip-6551). The main differences are:

- account addresses and creation do not depend on a `tokenId` or `tokenContract`
- a registry corresponds to an individual external service, and stores an updateable signing address controlled by the service

### Registry

The registry has two functions:

- `createAccount` - deploys a smart contract account for a user given an `implementation` address, salt, and signed message from the external service
- `account` - a read-only function that computes the smart contract account address for a user given an `implementation` address and salt

The registry SHALL deploy each account as an [ERC-1167](https://eips.ethereum.org/EIPS/eip-1167) proxy.

Each proxy deployed by the registry SHALL have the following interface:

```solidity
interface IAccountProxy {
    function implementation() external view returns (address);
}
```

Each smart contract account proxy SHALL delegate execution to a contract that implements the `IAccount` interface.

External services SHOULD allow users to create accounts through their registry contracts by providing a signed message and user identifier.

The registry SHALL verify these signed messages on calls to `createAccount`. Messages and corresponding signatures SHALL include an address and an expiry timestamp in epoch seconds. The registry SHOULD revert the transaction if said address is not equal to `msg.sender`, or if the expiry timestamp is less than `block.timestamp`.

The registry SHALL deploy all account contracts using the `create2` opcode so that the account address is deterministic. The account address for each user SHALL be derived from the unique combination of implementation address, [EIP-155](./eip-155.md) chain ID, and a unique user identifier used as the salt.

The registry SHALL implement the following interface:

```solidity
interface IAccountRegistry {
    struct AuthorizationParams {
        uint256 expiration,
        bytes32 message,
        bytes calldata signature,
    }

    /// @dev The registry SHALL emit the AccountCreated event upon successful account creation
    event AccountCreated(
        address account,
        address implementation,
        uint256 chainId,
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
        address implementation,
        uint256 chainId,
        uint256 salt,
        AuthorizationParams calldata auth,
        bytes calldata initData
    ) external returns (address);

    /// @dev Returns the computed address of a smart contract account
    ///
    /// @return The computed address of the account
    function account(
        address implementation,
        uint256 chainId,
        uint256 salt
    ) external view returns (address);

    /// @dev Updates the signing address used to verify auth params
    ///
    /// Only callable by the owner of the registry.
    function setSigner(
        address signer
    ) external onlyOwner;
}
```

### Account Interface

All accounts SHOULD be created via the registry.

All account implementations MUST implement [ERC-165](https://eips.ethereum.org/EIPS/eip-165) interface detection.

All account implementations MUST implement [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) signature validation.

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

    /// @dev Accounts SHOULD implement a `setOwner` function which updates the
    /// address that has permission to call `executeCall`.
    ///
    /// Only callable by the owner of the account.
    function setOwner() onlyOwner external;
}
```

## Rationale

<!--
  The rationale fleshes out the specification by describing what motivated the design and why particular design decisions were made. It should describe alternate designs that were considered and related work, e.g. how the feature is supported in other languages.

  The current placeholder is acceptable for a draft.

  TODO: Remove this comment before submitting
-->

TBD

## Backwards Compatibility

<!--

  This section is optional.

  All EIPs that introduce backwards incompatibilities must include a section describing these incompatibilities and their severity. The EIP must explain how the author proposes to deal with these incompatibilities. EIP submissions without a sufficient backwards compatibility treatise may be rejected outright.

  The current placeholder is acceptable for a draft.

  TODO: Remove this comment before submitting
-->

No backward compatibility issues found.

## Test Cases

<!--
  This section is optional for non-Core EIPs.

  The Test Cases section should include expected input/output pairs, but may include a succinct set of executable tests. It should not include project build files. No new requirements may be be introduced here (meaning an implementation following only the Specification section should pass all tests here.)
  If the test suite is too large to reasonably be included inline, then consider adding it as one or more files in `../assets/eip-####/`. External links will not be allowed

  TODO: Remove this comment before submitting
-->

## Reference Implementation

<!--
  This section is optional.

  The Reference Implementation section should include a minimal implementation that assists in understanding or implementing this specification. It should not include project build files. The reference implementation is not a replacement for the Specification section, and the proposal should still be understandable without it.
  If the reference implementation is too large to reasonably be included inline, then consider adding it as one or more files in `../assets/eip-####/`. External links will not be allowed.

  TODO: Remove this comment before submitting
-->

## Security Considerations

<!--
  All EIPs must contain a section that discusses the security implications/considerations relevant to the proposed change. Include information that might be important for security discussions, surfaces risks and can be used throughout the life cycle of the proposal. For example, include security-relevant design decisions, concerns, important discussions, implementation-specific guidance and pitfalls, an outline of threats and risks and how they are being addressed. EIP submissions missing the "Security Considerations" section will be rejected. An EIP cannot proceed to status "Final" without a Security Considerations discussion deemed sufficient by the reviewers.

  The current placeholder is acceptable for a draft.

  TODO: Remove this comment before submitting
-->

Needs discussion.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
