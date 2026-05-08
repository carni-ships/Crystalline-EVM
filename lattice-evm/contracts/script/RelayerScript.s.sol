// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {BlockHashRelay} from "../verifier/BlockHashRelay.sol";

/// @notice Relayer script to commit block hashes and state roots
/// @dev Usage:
///      forge script script/RelayerScript.s.sol:RelayerScript \
///        --sig "commitBlockHashesAndStateRoots(uint256[],bytes32[],bytes32[])" \
///        "[100,101,102]" \
///        "[0xhash1,0xhash2,0xhash3]" \
///        "[0xroot1,0xroot2,0xroot3]"
contract RelayerScript is Script {
    BlockHashRelay public relay;

    /// @notice Set up the relayer with a deployed relay address
    function setUp(address relayAddress) internal {
        relay = BlockHashRelay(relayAddress);
    }

    /// @notice Commit pre-provided block hashes and state roots in batch
    /// @param blockNumbers Array of block numbers (must be strictly increasing)
    /// @param blockHashes_ Array of corresponding block hashes
    /// @param stateRoots_ Array of corresponding state roots
    function commitBlockHashesAndStateRoots(
        uint256[] calldata blockNumbers,
        bytes32[] calldata blockHashes_,
        bytes32[] calldata stateRoots_
    ) public {
        require(address(relay) != address(0), "Relay not set up");
        relay.commitBlockHashesAndStateRoots(blockNumbers, blockHashes_, stateRoots_);
        console.log("Committed", blockNumbers.length, "block hashes and state roots");
    }

    /// @notice Commit block hash and state root for a single block
    /// @param blockNumber The block number to commit
    /// @param blockHash The canonical block hash
    /// @param stateRoot The canonical state root
    function commitSingleBlockWithStateRoot(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot
    ) public {
        require(address(relay) != address(0), "Relay not set up");
        relay.commitBlockHashAndStateRoot(blockNumber, blockHash, stateRoot);
        console.log("Committed block hash and state root for block", blockNumber);
    }

    /// @notice Commit pre-provided block hashes only (legacy single-field)
    /// @param blockNumbers Array of block numbers (must be strictly increasing)
    /// @param blockHashes_ Array of corresponding block hashes
    function commitBlockHashes(
        uint256[] calldata blockNumbers,
        bytes32[] calldata blockHashes_
    ) public {
        require(address(relay) != address(0), "Relay not set up");
        relay.commitBlockHashes(blockNumbers, blockHashes_);
        console.log("Committed", blockNumbers.length, "block hashes");
    }

    /// @notice Commit block hash for a single block (legacy single-field)
    /// @param blockNumber The block number to commit
    /// @param blockHash The canonical block hash
    function commitSingleBlock(uint256 blockNumber, bytes32 blockHash) public {
        require(address(relay) != address(0), "Relay not set up");
        relay.commitBlockHash(blockNumber, blockHash);
        console.log("Committed block hash for block", blockNumber);
    }

    /// @notice Run the relayer script
    /// @dev Default entry point for forge script
    function run() external {
        address relayAddress = vm.envOr("BLOCK_HASH_RELAY", address(0));

        if (relayAddress == address(0)) {
            console.log("No relay address provided, deploying new BlockHashRelay...");
            vm.startBroadcast();
            BlockHashRelay newRelay = new BlockHashRelay();
            relayAddress = address(newRelay);
            vm.stopBroadcast();
            console.log("BlockHashRelay deployed at:", relayAddress);
        }

        relay = BlockHashRelay(relayAddress);
        console.log("Using BlockHashRelay at:", relayAddress);
    }
}