// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import { IEAS, Attestation } from "../interfaces/IEAS.sol";
import { IResolver } from "../interfaces/IResolver.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { AccessDenied, InvalidEAS, InvalidLength, uncheckedInc, EMPTY_UID, NO_EXPIRATION_TIME, Session, slice } from "../Common.sol";

error AlreadyHasResponse();
error InsufficientValue();
error InvalidAttestationTitle();
error InvalidExpiration();
error InvalidRefUID();
error InvalidRevocability();
error InvalidRole();
error InvalidWithdraw();
error NotPayable();
error Unauthorized();
error InvalidSession();
error NotHostOfTheSession();

/// @author Blockful | 0xneves
/// @notice ZuVillage Resolver contract for Ethereum Attestation Service.
contract Resolver is IResolver, AccessControl {
  // The global EAS contract.
  IEAS internal immutable _eas;

  // Roles
  bytes32 public constant ROOT_ROLE = keccak256("ROOT_ROLE");
  bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
  bytes32 public constant VILLAGER_ROLE = keccak256("VILLAGER_ROLE");

  // Maps addresses to booleans to check if a Manager has been revoked
  mapping(address => bool) private _receivedManagerBadge;

  // Maps allowed attestations (Hashed titles that can be attested)
  mapping(bytes32 => bool) private _allowedAttestationTitles;

  // Maps attestation IDs to boolans (each attestation can only have one active response)
  mapping(bytes32 => bool) private _cannotReply;

  // Maps schemas ID and role ID to action
  mapping(bytes32 => Action) private _allowedSchemas;

  // Maps session ids and sessions Structures
  mapping(bytes32 => Session) private _session;

  // Maps all attestation titles (badge titles) to be retrieved by the frontend
  string[] private _attestationTitles;

  // Define a constant for default SESSION_DURATION (30 days in seconds)
  uint256 private constant DEFAULT_SESSION_DURATION = 30 days;

  /// @dev Creates a new resolver.
  /// @param eas The address of the global EAS contract.
  constructor(IEAS eas) {
    if (address(eas) == address(0)) revert InvalidEAS();
    _eas = eas;

    // Assigns ROOT_ROLE as the admin of all roles
    _setRoleAdmin(ROOT_ROLE, ROOT_ROLE);
    _setRoleAdmin(MANAGER_ROLE, ROOT_ROLE);
    _setRoleAdmin(VILLAGER_ROLE, ROOT_ROLE);

    // Assigns all roles to the deployer
    _grantRole(ROOT_ROLE, msg.sender);
    _grantRole(MANAGER_ROLE, msg.sender);
    _grantRole(VILLAGER_ROLE, msg.sender);
  }

  /// @dev Ensures that only the EAS contract can make this call.
  modifier onlyEAS() {
    if (msg.sender != address(_eas)) revert AccessDenied();
    _;
  }

  /// @inheritdoc IResolver
  function isPayable() public pure virtual returns (bool) {
    return false;
  }

  /// @inheritdoc IResolver
  function allowedAttestationTitles(string memory title) public view returns (bool) {
    return _allowedAttestationTitles[keccak256(abi.encode(title))];
  }

  /// @inheritdoc IResolver
  function cannotReply(bytes32 uid) public view returns (bool) {
    return _cannotReply[uid];
  }

  /// @inheritdoc IResolver
  function allowedSchemas(bytes32 uid) public view returns (Action) {
    return _allowedSchemas[uid];
  }

  /// @dev Validates if the `action` is allowed for the given `role` and `schema`.
  function isActionAllowed(bytes32 uid, Action action) internal view returns (bool) {
    return _allowedSchemas[uid] == action;
  }

  /// @inheritdoc IResolver
  function attest(Attestation calldata attestation) external payable onlyEAS returns (bool) {
    // Prohibits the attestation expiration to be finite
    if (attestation.expirationTime != NO_EXPIRATION_TIME) revert InvalidExpiration();

    // Schema to assign managers
    if (isActionAllowed(attestation.schema, Action.ASSIGN_MANAGER))
      return assignManager(attestation);

    // Schema to checkIn / checkOut villagers
    if (isActionAllowed(attestation.schema, Action.ASSIGN_VILLAGER)) {
      return assignVillager(attestation);
    }

    // Schema to create event attestations (Attestations)
    if (isActionAllowed(attestation.schema, Action.ATTEST)) {
      return attestEvent(attestation);
    }

    // Schema to create a response ( true / false )
    if (isActionAllowed(attestation.schema, Action.REPLY)) {
      return attestResponse(attestation);
    }

    return false;
  }

  /// @inheritdoc IResolver
  function revoke(Attestation calldata attestation) external payable onlyEAS returns (bool) {
    // Schema to revoke managers
    if (isActionAllowed(attestation.schema, Action.ASSIGN_MANAGER)) {
      _checkRole(ROOT_ROLE, attestation.attester);
      _checkRole(MANAGER_ROLE, attestation.recipient);
      _revokeRole(MANAGER_ROLE, attestation.recipient);
      return true;
    }

    // Schema to revoke a response ( true / false )
    if (isActionAllowed(attestation.schema, Action.REPLY)) {
      _checkRole(VILLAGER_ROLE, attestation.attester);
      _cannotReply[attestation.refUID] = false;
      return true;
    }

    return false;
  }

  /// @dev Assign new managers to the contract.
  function assignManager(Attestation calldata attestation) internal returns (bool) {
    if (hasRole(ROOT_ROLE, attestation.attester) || hasRole(MANAGER_ROLE, attestation.attester)) {
      if (
        hasRole(MANAGER_ROLE, attestation.recipient) || _receivedManagerBadge[attestation.recipient]
      ) revert InvalidRole();
      if (!attestation.revocable) revert InvalidRevocability();

      string memory role = abi.decode(attestation.data, (string));
      if (keccak256(abi.encode(role)) != keccak256(abi.encode("Manager"))) revert InvalidRole();

      _receivedManagerBadge[attestation.recipient] = true;
      _grantRole(MANAGER_ROLE, attestation.recipient);
      return true;
    }

    return false;
  }

  /// @dev Assign new villagers by checking in or revoke them by checking out.
  function assignVillager(Attestation calldata attestation) internal returns (bool) {
    if (attestation.revocable) revert InvalidRevocability();

    string memory status = abi.decode(attestation.data, (string));

    // Check if recipient doesn't have Villager Role (check-in)
    if (
      !hasRole(VILLAGER_ROLE, attestation.recipient) &&
      keccak256(abi.encode(status)) == keccak256(abi.encode("Check-in"))
    ) {
      _checkRole(MANAGER_ROLE, attestation.attester);
      _grantRole(VILLAGER_ROLE, attestation.recipient);
      return true;
    }

    // Check if recipient has Villager Role (check-out)
    if (
      hasRole(VILLAGER_ROLE, attestation.recipient) &&
      keccak256(abi.encode(status)) == keccak256(abi.encode("Check-out")) &&
      (attestation.recipient == attestation.attester || hasRole(MANAGER_ROLE, attestation.attester))
    ) {
      // Checks if the attestation has a non empty reference
      if (attestation.refUID == EMPTY_UID) revert InvalidRefUID();
      Attestation memory attesterRef = _eas.getAttestation(attestation.refUID);
      // Match the attester of this attestation with the recipient of the reference attestation
      // The check-out is designed to be a reply to a previous check-in
      if (attesterRef.recipient != attestation.recipient) revert InvalidRefUID();

      _revokeRole(VILLAGER_ROLE, attestation.recipient);
      return true;
    }

    return false;
  }

  /// @dev Attest an event badge.
  function attestEvent(Attestation calldata attestation) internal view returns (bool) {
    if (attestation.revocable) revert InvalidRevocability();
    _checkRole(VILLAGER_ROLE, attestation.attester);
    _checkRole(VILLAGER_ROLE, attestation.recipient);

    // Titles for attestations must be included in this contract by the managers
    // via the {setAttestationTitle} function
    (string memory title, ) = abi.decode(attestation.data, (string, string));
    if (!_allowedAttestationTitles[keccak256(abi.encode(title))]) revert InvalidAttestationTitle();

    // Check if it is a host-only attestation and if the attester is the host
    if (isHostOnlyAttestation(title)) {
      if (!isAttesterHost(attestation.attester, title)) revert NotHostOfTheSession();
    }

    return true;
  }

  /// @dev Checks if the attestation is a host-only attestation
  function isHostOnlyAttestation(string memory title) internal pure returns (bool) {
    bytes memory titleBytes = bytes(title);
    return
      titleBytes.length >= 5 &&
      (keccak256(abi.encodePacked(slice(titleBytes, 0, 5))) == keccak256("Host_") ||
        keccak256(abi.encodePacked(slice(titleBytes, 0, 9))) == keccak256("Attendee_"));
  }

  /// @dev Checks if the attester is the host of the session
  function isAttesterHost(address attester, string memory title) internal view returns (bool) {
    bytes memory titleBytes = bytes(title);
    string memory sessionTitle = string(slice(titleBytes, 5, titleBytes.length - 5));
    bytes32 sessionId = keccak256(abi.encodePacked(attester, sessionTitle));

    return _session[sessionId].host == attester;
  }

  /// @dev Attest a response to an event badge emitted by {attestEvent}.
  function attestResponse(Attestation calldata attestation) internal returns (bool) {
    if (!attestation.revocable) revert InvalidRevocability();
    if (_cannotReply[attestation.refUID]) revert AlreadyHasResponse();
    _checkRole(VILLAGER_ROLE, attestation.attester);

    // Checks if the attestation has a non empty reference
    if (attestation.refUID == EMPTY_UID) revert InvalidRefUID();
    Attestation memory attesterRef = _eas.getAttestation(attestation.refUID);
    // Match the attester of this attestation with the recipient of the reference attestation
    // The response is designed to be a reply to a previous attestation
    if (attesterRef.recipient != attestation.attester) revert InvalidRefUID();

    // Cannot create new responses until this attestation is revoked
    _cannotReply[attestation.refUID] = true;

    return true;
  }

  /// @inheritdoc IResolver
  function getAllAttestationTitles() public view returns (string[] memory) {
    string[] memory titles = new string[](_attestationTitles.length);
    uint256 j = 0;
    for (uint256 i = 0; i < _attestationTitles.length; ) {
      if (_allowedAttestationTitles[keccak256(abi.encode(_attestationTitles[i]))]) {
        titles[j] = _attestationTitles[i];
        assembly {
          j := add(j, 1)
        }
      }
      assembly {
        i := add(i, 1)
      }
    }
    assembly {
      mstore(titles, j)
    }
    return titles;
  }

  /// @inheritdoc IResolver
  function setAttestationTitle(string memory title, bool isValid) public onlyRole(MANAGER_ROLE) {
    _allowedAttestationTitles[keccak256(abi.encode(title))] = isValid;
    if (isValid) _attestationTitles.push(title);
  }

  /// @inheritdoc IResolver
  function setSchema(bytes32 uid, uint256 action) public onlyRole(ROOT_ROLE) {
    _allowedSchemas[uid] = Action(action);
  }

  /// @dev creates a new session
  function createSession(
    uint256 duration,
    string memory sessionTitle
  ) public returns (bytes32 sessionId) {
    if (!hasRole(VILLAGER_ROLE, msg.sender)) revert InvalidRole();
    if (duration == 0) revert InvalidSession();
    if (bytes(sessionTitle).length == 0) revert InvalidSession();

    // Generate a unique session ID
    sessionId = keccak256(abi.encodePacked(msg.sender, sessionTitle));

    // Check if the session already exists
    if (_session[sessionId].host != address(0)) {
      revert InvalidSession();
    }

    uint256 sessionDuration = duration > 0 ? duration : DEFAULT_SESSION_DURATION;
    Session memory session = Session({
      host: msg.sender,
      title: sessionTitle,
      startTime: block.timestamp,
      endTime: block.timestamp + sessionDuration
    });

    //Store the session
    _session[sessionId] = session;

    //Enable the host and attendee attestation related to the session
    string memory hostAttestationTitle = string(abi.encodePacked("Host_", sessionTitle));
    _allowedAttestationTitles[keccak256(abi.encode(hostAttestationTitle))] = true;
    string memory attendeeAttestationTitle = string(abi.encodePacked("Attendee_", sessionTitle));
    _allowedAttestationTitles[keccak256(abi.encode(attendeeAttestationTitle))] = true;

    return sessionId;
  }

  /// @dev Remove a session.
  function removeSesison(
    string memory sessionTitle,
    address sessionOwner
  ) external onlyRole(ROOT_ROLE) {
    bytes32 sessionId = keccak256(abi.encodePacked(sessionOwner, sessionTitle));
    delete _session[sessionId];
  }

  /// @dev Get a session.
  function getSession(
    string memory sessionTitle,
    address sessionOwner
  ) external view returns (Session memory) {
    bytes32 sessionId = keccak256(abi.encodePacked(sessionOwner, sessionTitle));
    return _session[sessionId];
  }

  /// @dev ETH callback.
  receive() external payable virtual {
    if (!isPayable()) {
      revert NotPayable();
    }
  }
}
