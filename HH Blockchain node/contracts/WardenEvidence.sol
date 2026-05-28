// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * WardenEvidence.sol
 *
 * Purpose:
 *     Stores tamper-evident forensic evidence hashes generated
 *     by the WARDEN intrusion detection system.
 *
 * Responsibilities:
 *     - Anchor evidence hashes on-chain
 *     - Store compact attack metadata
 *     - Prevent duplicate evidence insertion
 *     - Provide immutable blockchain timestamps
 *     - Emit forensic logging events
 *
 * Non-Responsibilities:
 *     - Storing raw packet captures
 *     - Managing full JSONL forensic logs
 *     - Performing off-chain verification logic
 *     - Executing IDS detection algorithms
 *
 * Architecture:
 *
 *      WARDEN IDS
 *            ↓
 *      JSONL Evidence
 *            ↓
 *      SHA-256 Hashing
 *            ↓
 *      WardenEvidence
 *            ↓
 *      Blockchain Verification
 */

/* -------------------------------------------------------------------------- */
/*                             Warden Evidence                                */
/* -------------------------------------------------------------------------- */

/**
 * @title WardenEvidence
 * @notice Immutable forensic evidence registry for the WARDEN IDS platform.
 * @dev
 * Stores compact attack metadata alongside SHA-256 evidence hashes
 * for tamper-evident blockchain anchoring.
 *
 * Full forensic payloads remain off-chain for scalability.
 */
contract WardenEvidence {
    /* ---------------------------------------------------------------------- */
    /*                                 Structs                                */
    /* ---------------------------------------------------------------------- */

    /**
     * @notice Represents a single anchored attack evidence record.
     */
    struct AttackRecord {
        /// @notice SHA-256 hash of off-chain forensic evidence.
        bytes32 evidenceHash;

        /// @notice Source IP associated with the attack.
        string sourceIp;

        /// @notice Network/application protocol involved.
        string protocol;

        /// @notice Protocol-specific message type.
        string messageType;

        /**
         * @notice Packets-per-second value multiplied by 1000.
         * @dev Used to preserve fixed-point precision.
         */
        uint256 ppsMilli;

        /// @notice Whether mitigation was applied.
        bool mitigated;

        /// @notice Block timestamp when evidence was anchored.
        uint256 timestamp;

        /// @notice Address that submitted the evidence.
        address reporter;
    }

    /* ---------------------------------------------------------------------- */
    /*                              State Variables                           */
    /* ---------------------------------------------------------------------- */

    /// @notice Immutable registry owner.
    address public immutable owner;

    /// @notice Human-readable registry name.
    string public name;

    /// @notice Append-only evidence storage array.
    AttackRecord[] private records;

    /**
     * @notice Tracks whether an evidence hash already exists.
     * @dev Prevents duplicate forensic anchoring.
     */
    mapping(bytes32 => bool) public evidenceExists;

    /* ---------------------------------------------------------------------- */
    /*                                  Events                                */
    /* ---------------------------------------------------------------------- */

    /**
     * @notice Emitted whenever attack evidence is anchored.
     *
     * @param recordId Index of the stored record.
     * @param evidenceHash SHA-256 evidence hash.
     * @param reporter Address that submitted the evidence.
     * @param sourceIp Source IP tied to the attack.
     * @param protocol Protocol involved in the event.
     * @param messageType Protocol message type.
     * @param ppsMilli Packets/sec multiplied by 1000.
     * @param mitigated Whether mitigation was applied.
     * @param timestamp Blockchain timestamp of submission.
     */
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

    /* ---------------------------------------------------------------------- */
    /*                                   Errors                               */
    /* ---------------------------------------------------------------------- */

    /// @notice Thrown when duplicate evidence is submitted.
    error DuplicateEvidence(bytes32 evidenceHash);

    /// @notice Thrown when an empty evidence hash is submitted.
    error EmptyEvidenceHash();

    /// @notice Thrown when a non-owner accesses restricted logic.
    error NotOwner();

    /* ---------------------------------------------------------------------- */
    /*                                  Modifiers                             */
    /* ---------------------------------------------------------------------- */

    /**
     * @notice Restricts execution to the registry owner.
     */
    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /* ---------------------------------------------------------------------- */
    /*                               Constructor                              */
    /* ---------------------------------------------------------------------- */

    /**
     * @notice Initializes a new WARDEN evidence registry.
     *
     * @param _name Human-readable registry name.
     * @param _owner Registry owner address.
     */
    constructor(string memory _name, address _owner) {
        name = _name;
        owner = _owner;
    }

    /* ---------------------------------------------------------------------- */
    /*                            External Functions                          */
    /* ---------------------------------------------------------------------- */

    /**
     * @notice Anchors attack evidence on-chain.
     *
     * @dev
     * Stores compact forensic metadata alongside a SHA-256 hash
     * of off-chain evidence logs.
     *
     * Requirements:
     * - Evidence hash cannot be zero
     * - Evidence hash must not already exist
     *
     * @param evidenceHash SHA-256 hash of forensic evidence.
     * @param sourceIp Source IP tied to the event.
     * @param protocol Protocol involved in the attack.
     * @param messageType Protocol message classification.
     * @param ppsMilli Packets/sec multiplied by 1000.
     * @param mitigated Whether mitigation was applied.
     *
     * @return recordId Index of the newly stored record.
     */
    function logAttack(
        bytes32 evidenceHash,
        string calldata sourceIp,
        string calldata protocol,
        string calldata messageType,
        uint256 ppsMilli,
        bool mitigated
    ) external returns (uint256 recordId) {
        if (evidenceHash == bytes32(0)) revert EmptyEvidenceHash();

        if (evidenceExists[evidenceHash]) {
            revert DuplicateEvidence(evidenceHash);
        }

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

    /* ---------------------------------------------------------------------- */
    /*                              View Functions                            */
    /* ---------------------------------------------------------------------- */

    /**
     * @notice Returns total anchored evidence records.
     *
     * @return Total record count.
     */
    function recordCount() external view returns (uint256) {
        return records.length;
    }

    /**
     * @notice Returns a specific evidence record.
     *
     * @param recordId Index of the record.
     *
     * @return Requested attack record.
     */
    function getRecord(
        uint256 recordId
    ) external view returns (AttackRecord memory) {
        return records[recordId];
    }

    /**
     * @notice Returns the most recently anchored evidence record.
     *
     * @return Latest attack record.
     */
    function getLatestRecord()
        external
        view
        returns (AttackRecord memory)
    {
        require(records.length > 0, "NO_RECORDS");

        return records[records.length - 1];
    }
}