// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./WardenEvidence.sol";

/// @title WardenEvidenceFactory
/// @notice Deploys WardenEvidence registries for different IPS deployments/sites.
contract WardenEvidenceFactory {
    address[] private registries;
    mapping(address => address[]) private registriesByOwner;

    event RegistryCreated(
        address indexed registry,
        address indexed owner,
        string name,
        uint256 indexed index
    );

    function createRegistry(string calldata name) external returns (address registry) {
        WardenEvidence evidence = new WardenEvidence(name, msg.sender);
        registry = address(evidence);

        registries.push(registry);
        registriesByOwner[msg.sender].push(registry);

        emit RegistryCreated(registry, msg.sender, name, registries.length - 1);
    }

    function registryCount() external view returns (uint256) {
        return registries.length;
    }

    function getRegistry(uint256 index) external view returns (address) {
        return registries[index];
    }

    function getRegistries() external view returns (address[] memory) {
        return registries;
    }

    function getRegistriesByOwner(address owner) external view returns (address[] memory) {
        return registriesByOwner[owner];
    }
}
