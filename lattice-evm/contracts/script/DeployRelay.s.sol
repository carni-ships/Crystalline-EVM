// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {BlockHashRelay} from "../verifier/BlockHashRelay.sol";

/// @notice Deploy script for BlockHashRelay
/// @dev Usage:
///      forge script script/DeployRelay.s.sol:DeployRelayScript \
///        --rpc-url $ETH_RPC --broadcast --private-key $PRIVATE_KEY
contract DeployRelayScript is Script {
    function run() external {
        vm.startBroadcast();

        BlockHashRelay relay = new BlockHashRelay();
        console.log("BlockHashRelay deployed at:", address(relay));
        console.log("State roots support: ENABLED");

        vm.stopBroadcast();
    }
}