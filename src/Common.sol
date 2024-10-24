// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

// A representation of an empty/uninitialized UID.
bytes32 constant EMPTY_UID = 0;

// A zero expiration represents an non-expiring attestation.
uint64 constant NO_EXPIRATION_TIME = 0;

error AccessDenied();
error DeadlineExpired();
error InvalidEAS();
error InvalidLength();
error InvalidSignature();
error NotFound();

/// @notice A struct representing ECDSA signature data.
struct Signature {
  uint8 v; // The recovery ID.
  bytes32 r; // The x-coordinate of the nonce R.
  bytes32 s; // The signature data.
}

/// @notice A struct representing a single attestation.
struct Attestation {
  bytes32 uid; // A unique identifier of the attestation.
  bytes32 schema; // The unique identifier of the schema.
  uint64 time; // The time when the attestation was created (Unix timestamp).
  uint64 expirationTime; // The time when the attestation expires (Unix timestamp).
  uint64 revocationTime; // The time when the attestation was revoked (Unix timestamp).
  bytes32 refUID; // The UID of the related attestation.
  address recipient; // The recipient of the attestation.
  address attester; // The attester/sender of the attestation.
  bool revocable; // Whether the attestation is revocable.
  bytes data; // Custom attestation data.
}

/// @notice A struct representing a single Session.
struct Session {
  address host; // Host of the session
  string title; // Title of the session
  uint256 startTime; // The time when the session was created (Unix timestamp).
  uint256 endTime; // The time when the session was ended (Unix timestamp).
}

/// @notice A helper function to work with unchecked iterators in loops.
function uncheckedInc(uint256 i) pure returns (uint256 j) {
  unchecked {
    j = i + 1;
  }
}

/// @dev Helper function to slice a byte array
function slice(bytes memory data, uint256 start, uint256 length) pure returns (bytes memory) {
  bytes memory result = new bytes(length);
  for (uint i = 0; i < length; i++) {
    result[i] = data[start + i];
  }
  return result;
}
