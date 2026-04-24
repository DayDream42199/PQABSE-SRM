// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract RootRegistry {
    address public owner;
    uint256 public currentEpoch;
    bytes32 public registrationRoot;
    bytes32 public revocationRoot;

    event RootsUpdated(
        uint256 indexed epoch,
        bytes32 registrationRoot,
        bytes32 revocationRoot
    );

    event RegistrationRootUpdated(
        uint256 indexed epoch,
        bytes32 registrationRoot
    );

    event GenesisRootsBootstrapped(
        bytes32 registrationRoot,
        bytes32 revocationRoot
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(bytes32 initialRegistrationRoot, bytes32 initialRevocationRoot) {
        owner = msg.sender;
        currentEpoch = 0;
        registrationRoot = initialRegistrationRoot;
        revocationRoot = initialRevocationRoot;

        emit RootsUpdated(currentEpoch, initialRegistrationRoot, initialRevocationRoot);
    }

    function updateRoots(
        uint256 newEpoch,
        bytes32 newRegistrationRoot,
        bytes32 newRevocationRoot
    ) external onlyOwner {
        require(newEpoch > currentEpoch, "epoch must increase");

        currentEpoch = newEpoch;
        registrationRoot = newRegistrationRoot;
        revocationRoot = newRevocationRoot;

        emit RootsUpdated(newEpoch, newRegistrationRoot, newRevocationRoot);
    }

    function bootstrapGenesisRoots(
        bytes32 newRegistrationRoot,
        bytes32 newRevocationRoot
    ) external onlyOwner {
        require(currentEpoch == 0, "genesis already advanced");
        require(
            registrationRoot == bytes32(0) && revocationRoot == bytes32(0),
            "genesis roots already set"
        );

        registrationRoot = newRegistrationRoot;
        revocationRoot = newRevocationRoot;

        emit GenesisRootsBootstrapped(newRegistrationRoot, newRevocationRoot);
        emit RootsUpdated(currentEpoch, newRegistrationRoot, newRevocationRoot);
    }

    function updateRegistrationRoot(bytes32 newRegistrationRoot) external onlyOwner {
        registrationRoot = newRegistrationRoot;
        emit RegistrationRootUpdated(currentEpoch, newRegistrationRoot);
    }

    function getCurrentState()
        external
        view
        returns (uint256 epoch, bytes32 regRoot, bytes32 revRoot)
    {
        return (currentEpoch, registrationRoot, revocationRoot);
    }
}
