// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WardenEvidence
/// @notice Stores tamper-evident IPS attack evidence hashes produced by The Warden.
/// @dev Designed for local Hardhat first. Store detailed evidence off-chain in JSONL/IPFS.
///      Store only the evidence hash and compact metadata on-chain.
contract WardenEvidence {
    struct AttackRecord {
        bytes32 evidenceHash;
        string sourceIp;
        string protocol;
        string messageType;
        uint256 ppsMilli;
        bool mitigated;
        uint256 timestamp;
        address reporter;
    }

    address public immutable owner;
    string public name;

    AttackRecord[] private records;
    mapping(bytes32 => bool) public evidenceExists;

    event AttackLogged(
        uint256 indexed recordId,
        bytes32 indexed evidenceHash,
        address indexed reporter,
        string sourceIp,
        string protocol,
        string messageType,
        uint256 ppsMilli,
        bool mitigated,
        uint256 timestamp
    );

    error DuplicateEvidence(bytes32 evidenceHash);
    error EmptyEvidenceHash();
    error NotOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(string memory _name, address _owner) {
        name = _name;
        owner = _owner;
    }

    /// @notice Log one Warden attack evidence record.
    /// @param evidenceHash SHA-256/Keccak-style 32-byte evidence hash from off-chain JSONL evidence.
    /// @param sourceIp Source IP as string for local demo. Later, replace with sourceIpHash for privacy.
    /// @param protocol Protocol name, e.g. MQTT or CoAP.
    /// @param messageType Protocol message type, e.g. PUBLISH, CONNECT, GET.
    /// @param ppsMilli Packets/sec multiplied by 1000. Example: 1.234 PPS => 1234.
    /// @param mitigated Whether the IPS mitigation action was attempted/applied.
    function logAttack(
        bytes32 evidenceHash,
        string calldata sourceIp,
        string calldata protocol,
        string calldata messageType,
        uint256 ppsMilli,
        bool mitigated
    ) external returns (uint256 recordId) {
        if (evidenceHash == bytes32(0)) revert EmptyEvidenceHash();
        if (evidenceExists[evidenceHash]) revert DuplicateEvidence(evidenceHash);

        evidenceExists[evidenceHash] = true;

        recordId = records.length;

        records.push(
            AttackRecord({
                evidenceHash: evidenceHash,
                sourceIp: sourceIp,
                protocol: protocol,
                messageType: messageType,
                ppsMilli: ppsMilli,
                mitigated: mitigated,
                timestamp: block.timestamp,
                reporter: msg.sender
            })
        );

        emit AttackLogged(
            recordId,
            evidenceHash,
            msg.sender,
            sourceIp,
            protocol,
            messageType,
            ppsMilli,
            mitigated,
            block.timestamp
        );
    }

    function recordCount() external view returns (uint256) {
        return records.length;
    }

    function getRecord(uint256 recordId) external view returns (AttackRecord memory) {
        return records[recordId];
    }

    function getLatestRecord() external view returns (AttackRecord memory) {
        require(records.length > 0, "NO_RECORDS");
        return records[records.length - 1];
    }
}
