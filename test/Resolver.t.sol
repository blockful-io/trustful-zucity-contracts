// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/src/Test.sol";
import { Resolver, NotHostOfTheSession, InvalidRole, InvalidSession } from "../src/resolver/Resolver.sol";
import { IResolver } from "../src/interfaces/IResolver.sol";
import { ISchemaRegistry } from "../src/interfaces/ISchemaRegistry.sol";
import { IEAS, AttestationRequest, AttestationRequestData } from "../src/interfaces/IEAS.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";

contract ResolverTest is Test {
  IEAS eas = IEAS(0x4200000000000000000000000000000000000021);
  ISchemaRegistry schemaRegistry = ISchemaRegistry(0x4200000000000000000000000000000000000020);
  IResolver resolver;

  bytes32 ROOT_ROLE = keccak256("ROOT_ROLE");
  bytes32 MANAGER_ROLE = keccak256("MANAGER_ROLE");
  bytes32 VILLAGER_ROLE = keccak256("VILLAGER_ROLE");

  address deployer = 0xF977814e90dA44bFA03b6295A0616a897441aceC;
  address roleReceiver = 0x96DB2c6D93A8a12089f7a6EdA5464e967308AdEd;

  function setUp() public {
    vm.label(deployer, "deployer");
    vm.label(roleReceiver, "roleReceiver");
    vm.startPrank(deployer);
    resolver = new Resolver(eas);
  }

  function test_access_control_all_badge_titles() public {
    string[] memory registeredTitles = test_access_control_add_attest_title();
    string[] memory allTitles = resolver.getAllAttestationTitles();
    assert(allTitles.length == registeredTitles.length);
    for (uint256 i = 0; i < allTitles.length; i++) {
      assert(keccak256(abi.encode(allTitles[i])) == keccak256(abi.encode(registeredTitles[i])));
    }
    resolver.setAttestationTitle(registeredTitles[0], false);
    allTitles = resolver.getAllAttestationTitles();
    assert(allTitles.length == registeredTitles.length - 1);
    assert(keccak256(abi.encode(allTitles[0])) != keccak256(abi.encode(registeredTitles[0])));
    assert(keccak256(abi.encode(allTitles[0])) == keccak256(abi.encode(registeredTitles[1])));
    assert(keccak256(abi.encode(allTitles[1])) == keccak256(abi.encode(registeredTitles[2])));
  }

  function test_access_control_add_attest_title() public returns (string[] memory) {
    string[] memory titles = new string[](3);
    titles[0] = "Changed My Mind";
    titles[1] = "Is a good person";
    titles[2] = "Has a brilliant mind";

    resolver.setAttestationTitle(titles[0], true);
    assert(resolver.allowedAttestationTitles(titles[0]));

    resolver.setAttestationTitle(titles[1], true);
    assert(resolver.allowedAttestationTitles(titles[1]));

    resolver.setAttestationTitle(titles[2], true);
    assert(resolver.allowedAttestationTitles(titles[2]));

    return titles;
  }

  function test_access_control_revoke_attest_title() public {
    string[] memory titles = test_access_control_add_attest_title();

    resolver.setAttestationTitle(titles[0], false);
    assert(!resolver.allowedAttestationTitles(titles[0]));

    resolver.setAttestationTitle(titles[1], false);
    assert(!resolver.allowedAttestationTitles(titles[1]));

    resolver.setAttestationTitle(titles[2], false);
    assert(!resolver.allowedAttestationTitles(titles[2]));
  }

  function test_access_control_add_schemas() public returns (bytes32[] memory) {
    bytes32[] memory uids = new bytes32[](4);

    /// ASSIGN MANAGER SCHEMA
    string memory schema = "string role";
    bool revocable = true;
    bytes32 uid = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uid, 1);
    assert(resolver.allowedSchemas(uid) == IResolver.Action.ASSIGN_MANAGER);
    uids[0] = uid;

    /// ASSIGN VILLAGER SCHEMA
    schema = "string status";
    revocable = false;
    uid = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uid, 2);
    assert(resolver.allowedSchemas(uid) == IResolver.Action.ASSIGN_VILLAGER);
    uids[1] = uid;

    /// Event Attestation SCHEMA
    schema = "string title,string comment";
    revocable = false;
    uid = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uid, 3);
    assert(resolver.allowedSchemas(uid) == IResolver.Action.ATTEST);
    uids[2] = uid;

    /// Event Response SCHEMA
    schema = "bool status";
    revocable = true;
    uid = schemaRegistry.register(schema, resolver, revocable);
    resolver.setSchema(uid, 4);
    assert(resolver.allowedSchemas(uid) == IResolver.Action.REPLY);
    uids[3] = uid;

    return uids;
  }

  function test_access_control_revoke_schemas() public {
    bytes32[] memory uids = test_access_control_add_schemas();

    /// MANAGER SCHEMA
    resolver.setSchema(uids[0], 0);
    assert(resolver.allowedSchemas(uids[0]) == IResolver.Action.NONE);

    /// VILLAGER SCHEMA
    resolver.setSchema(uids[1], 0);
    assert(resolver.allowedSchemas(uids[1]) == IResolver.Action.NONE);

    /// Event Attestation SCHEMA
    resolver.setSchema(uids[2], 0);
    assert(resolver.allowedSchemas(uids[2]) == IResolver.Action.NONE);

    /// Event Response SCHEMA
    resolver.setSchema(uids[3], 0);
    assert(resolver.allowedSchemas(uids[3]) == IResolver.Action.NONE);
  }

  function test_access_control_create_roles() public {
    // Should not have the manager role at first
    assert(!hasRole(MANAGER_ROLE, roleReceiver));
    // Grant MANAGER_ROLE and check
    grantRole(MANAGER_ROLE, roleReceiver);
    assert(hasRole(MANAGER_ROLE, roleReceiver));
    // Should not have the villager at first
    assert(!hasRole(VILLAGER_ROLE, roleReceiver));
    // Grant VILLAGER_ROLE and check
    grantRole(VILLAGER_ROLE, roleReceiver);
    assert(hasRole(VILLAGER_ROLE, roleReceiver));
  }

  function test_access_control_revoke_roles() public {
    test_access_control_create_roles();

    assert(hasRole(MANAGER_ROLE, roleReceiver));
    revokeRole(MANAGER_ROLE, roleReceiver);
    assert(!hasRole(MANAGER_ROLE, roleReceiver));

    assert(hasRole(VILLAGER_ROLE, roleReceiver));
    revokeRole(VILLAGER_ROLE, roleReceiver);
    assert(!hasRole(VILLAGER_ROLE, roleReceiver));

    assert(hasRole(ROOT_ROLE, deployer));
    revokeRole(ROOT_ROLE, deployer);
    assert(!hasRole(ROOT_ROLE, deployer));
  }

  function hasRole(bytes32 role, address account) public view returns (bool) {
    return IAccessControl(address(resolver)).hasRole(role, account);
  }

  function grantRole(bytes32 role, address account) public {
    IAccessControl(address(resolver)).grantRole(role, account);
  }

  function revokeRole(bytes32 role, address account) public {
    IAccessControl(address(resolver)).revokeRole(role, account);
  }

  function test_host_attestation_allowed() public {
    bytes32[] memory uids = test_access_control_add_schemas();
    address host = roleReceiver;
    address atendee = address(0x5678);

    string memory sessionTitle = "TestSession";
    grantRole(VILLAGER_ROLE, roleReceiver);
    grantRole(VILLAGER_ROLE, atendee);

    // Create a session
    vm.startPrank(host);
    resolver.createSession(10, sessionTitle);

    // Prepare attestation data
    string memory hostTitle = string(abi.encodePacked("Host_", sessionTitle));
    bytes memory attestationData = abi.encode(hostTitle, "Test comment");

    // Create attestation request
    AttestationRequest memory request = AttestationRequest({
      schema: uids[2],
      data: AttestationRequestData({
        recipient: address(0x5678),
        expirationTime: 0,
        revocable: false,
        refUID: bytes32(0),
        data: attestationData,
        value: 0
      })
    });

    bytes32 attestationUID = eas.attest(request);
    vm.stopPrank();
    assertTrue(eas.isAttestationValid(attestationUID), "Attestation should be valid");
  }

  function test_host_attestation_not_allowed() public {
    // Setup
    bytes32[] memory uids = test_access_control_add_schemas();
    address host = roleReceiver;
    address atendee = address(0x5678);
    grantRole(VILLAGER_ROLE, atendee);
    grantRole(VILLAGER_ROLE, host);

    string memory sessionTitle = "TestSession";

    // Create a session
    vm.startPrank(host);
    resolver.createSession(10, sessionTitle);

    // Prepare attestation data
    string memory hostTitle = string(abi.encodePacked("Host_", sessionTitle));
    bytes memory attestationData = abi.encode(hostTitle, "Test comment");

    // Create attestation request
    AttestationRequest memory request = AttestationRequest({
      schema: uids[2],
      data: AttestationRequestData({
        recipient: host,
        expirationTime: 0,
        revocable: false,
        refUID: bytes32(0),
        data: attestationData,
        value: 0
      })
    });

    // Attempt to attest as a non-host
    vm.startPrank(atendee);
    vm.expectRevert(NotHostOfTheSession.selector);
    eas.attest(request);
    vm.stopPrank();
  }


  function test_attendee_attestation_allowed() public {
    bytes32[] memory uids = test_access_control_add_schemas();
    address host = roleReceiver;
    address atendee = address(0x5678);

    string memory sessionTitle = "TestSession";
    grantRole(VILLAGER_ROLE, roleReceiver);
    grantRole(VILLAGER_ROLE, atendee);

    // Create a session
    vm.startPrank(host);
    resolver.createSession(10, sessionTitle);

    // Prepare attestation data
    string memory attendeeTitle = string(abi.encodePacked("Attendee_", sessionTitle));
    bytes memory attestationData = abi.encode(attendeeTitle, "Test comment");

    // Create attestation request
    AttestationRequest memory request = AttestationRequest({
      schema: uids[2],
      data: AttestationRequestData({
        recipient: address(0x5678),
        expirationTime: 0,
        revocable: false,
        refUID: bytes32(0),
        data: attestationData,
        value: 0
      })
    });

    bytes32 attestationUID = eas.attest(request);
    vm.stopPrank();
    assertTrue(eas.isAttestationValid(attestationUID), "Attestation should be valid");
  }

  function test_create_session_as_villager() public {
    address villager = roleReceiver;
    string memory sessionTitle = "Test Session";
    uint256 duration = 1 days;

    grantRole(VILLAGER_ROLE, villager);

    vm.startPrank(villager);
    bytes32 sessionId = resolver.createSession(duration, sessionTitle);
    vm.stopPrank();

    assert(sessionId != bytes32(0));
  }

  function test_create_session_as_non_villager() public {
    address nonVillager = address(0x5678);
    string memory sessionTitle = "Test Session";
    uint256 duration = 1 days;
    grantRole(VILLAGER_ROLE, roleReceiver);

    vm.startPrank(nonVillager);
    vm.expectRevert(InvalidRole.selector);
    resolver.createSession(duration, sessionTitle);
  }

  function test_create_duplicate_session() public {
    address villager = roleReceiver;
    string memory sessionTitle = "Test Session";
    uint256 duration = 1 days;

    grantRole(VILLAGER_ROLE, villager);

    vm.startPrank(villager);
    resolver.createSession(duration, sessionTitle);

    vm.expectRevert(InvalidSession.selector);
    resolver.createSession(duration, sessionTitle);
    vm.stopPrank();
  }

  function test_session_attestation_titles_allowed() public {
    address villager = roleReceiver;
    string memory sessionTitle = "Test Session";
    uint256 duration = 1 days;

    grantRole(VILLAGER_ROLE, villager);

    vm.startPrank(villager);
    resolver.createSession(duration, sessionTitle);
    vm.stopPrank();

    string memory hostTitle = string(abi.encodePacked("Host_", sessionTitle));
    string memory attendeeTitle = string(abi.encodePacked("Attendee_", sessionTitle));

    assert(resolver.allowedAttestationTitles(hostTitle));
    assert(resolver.allowedAttestationTitles(attendeeTitle));
  }

  function test_create_session_with_zero_duration() public {
    address villager = roleReceiver;
    string memory sessionTitle = "Zero Duration Session";
    uint256 duration = 0;

    grantRole(VILLAGER_ROLE, villager);

    vm.startPrank(villager);
    vm.expectRevert(InvalidSession.selector);
    resolver.createSession(duration, sessionTitle);
    vm.stopPrank();
  }

  function test_create_session_with_empty_title() public {
    address villager = roleReceiver;
    string memory sessionTitle = "";
    uint256 duration = 1 days;

    grantRole(VILLAGER_ROLE, villager);

    vm.startPrank(villager);
    vm.expectRevert(InvalidSession.selector);
    resolver.createSession(duration, sessionTitle);
    vm.stopPrank();
  }

  function test_create_multiple_sessions() public {
    address villager = roleReceiver;
    string memory sessionTitle1 = "First Session";
    string memory sessionTitle2 = "Second Session";
    uint256 duration = 1 days;

    grantRole(VILLAGER_ROLE, villager);

    vm.startPrank(villager);

    bytes32 sessionId1 = resolver.createSession(duration, sessionTitle1);
    assert(sessionId1 != bytes32(0));

    bytes32 sessionId2 = resolver.createSession(duration, sessionTitle2);
    assert(sessionId2 != bytes32(0));

    assert(sessionId1 != sessionId2);

    vm.stopPrank();
  }

  function test_remove_session() public {
    address villager = roleReceiver;
    string memory sessionTitle = "Test Session";
    uint256 duration = 1 days;

    grantRole(VILLAGER_ROLE, villager);

    vm.startPrank(villager);
    bytes32 sessionId = resolver.createSession(duration, sessionTitle);
    vm.stopPrank();
    assert(sessionId != bytes32(0));

    vm.startPrank(deployer);
    resolver.removeSesison(sessionTitle, villager);
    vm.stopPrank();
    address host = resolver.getSession(sessionTitle, villager).host;
    assert(host == address(0));
  }

  function test_closeSession() public {
    // Setup
    address villager = roleReceiver;
    string memory sessionTitle = "Test Session";
    uint256 duration = 1 days;

    grantRole(VILLAGER_ROLE, villager);

    // Create a session
    vm.startPrank(villager);
    bytes32 sessionId = resolver.createSession(duration, sessionTitle);
    vm.stopPrank();

    // Fast forward time to ensure the session can be closed
    vm.warp(block.timestamp + duration - 1);

    // Close the session
    vm.startPrank(villager);
    resolver.closeSession(sessionId);
    vm.stopPrank();

    Resolver.Session memory session = resolver.getSession(sessionTitle, villager);
    assert(session.endTime == block.timestamp);
  }
}
