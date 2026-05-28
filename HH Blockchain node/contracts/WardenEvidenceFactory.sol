// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * WardenEvidenceFactory.sol
 *
 * Purpose:
 *     Deploys independent WardenEvidence registries
 *     for WARDEN IDS deployments.
 *
 * Responsibilities:
 *     - Deploy new WardenEvidence contracts
 *     - Track deployed registries
 *     - Maintain owner-to-registry mappings
 *     - Emit registry deployment metadata
 *
 * Non-Responsibilities:
 *     - Storing forensic evidence directly
 *     - Performing evidence verification
 *     - Running intrusion detection logic
 *     - Managing mitigation workflows
 *
 * Architecture:
 *
 *      WardenEvidenceFactory
 *                 ↓
 *        WardenEvidence Deployment
 *                 ↓
 *         Independent Registries
 *                 ↓
 *          Forensic Anchoring
 */

import "./WardenEvidence.sol";

/* -------------------------------------------------------------------------- */
/*                          Warden Evidence Factory                           */
/* -------------------------------------------------------------------------- */

/**
 * @title WardenEvidenceFactory
 * @notice Deploys isolated forensic evidence registries for WARDEN.
 * @dev
 * Each deployment receives:
 * - its own evidence registry
 * - independent storage
 * - separate ownership
 * - isolated forensic history
 */
contract WardenEvidenceFactory {
    /* ---------------------------------------------------------------------- */
    /*                              State Variables                           */
    /* ---------------------------------------------------------------------- */

    /// @notice Stores every registry deployed by the factory.
    address[] private registries;

    /**
     * @notice Maps owners to their deployed registries.
     */
    mapping(address => address[]) private registriesByOwner;

    /* ---------------------------------------------------------------------- */
    /*                                  Events                                */
    /* ---------------------------------------------------------------------- */

    /**
     * @notice Emitted when a new registry is deployed.
     *
     * @param registry Address of deployed registry.
     * @param owner Address that deployed the registry.
     * @param name Human-readable registry name.
     * @param index Global registry index.
     */
    event RegistryCreated(
        address indexed registry,
        address indexed owner,
        string name,
        uint256 indexed index
    );

    /* ---------------------------------------------------------------------- */
    /*                            External Functions                          */
    /* ---------------------------------------------------------------------- */

    /**
     * @notice Deploys a new WardenEvidence registry.
     *
     * @dev
     * The caller automatically becomes the registry owner.
     *
     * @param name Human-readable registry name.
     *
     * @return registry Address of the deployed registry.
     */
    function createRegistry(
        string calldata name
    ) external returns (address registry) {
        WardenEvidence evidence = new WardenEvidence(name, msg.sender);

        registry = address(evidence);

        registries.push(registry);
        registriesByOwner[msg.sender].push(registry);

        emit RegistryCreated(
            registry,
            msg.sender,
            name,
            registries.length - 1
        );
    }

    /* ---------------------------------------------------------------------- */
    /*                              View Functions                            */
    /* ---------------------------------------------------------------------- */

    /**
     * @notice Returns total deployed registries.
     *
     * @return Total registry count.
     */
    function registryCount() external view returns (uint256) {
        return registries.length;
    }

    /**
     * @notice Returns a registry address by index.
     *
     * @param index Registry index.
     *
     * @return Registry contract address.
     */
    function getRegistry(
        uint256 index
    ) external view returns (address) {
        return registries[index];
    }

    /**
     * @notice Returns all deployed registries.
     *
     * @return Array of registry addresses.
     */
    function getRegistries()
        external
        view
        returns (address[] memory)
    {
        return registries;
    }

    /**
     * @notice Returns registries owned by a specific address.
     *
     * @param owner Registry owner address.
     *
     * @return Array of owned registry addresses.
     */
    function getRegistriesByOwner(
        address owner
    ) external view returns (address[] memory) {
        return registriesByOwner[owner];
    }
}