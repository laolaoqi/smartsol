// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * EXAMPLE ONLY — intentionally vulnerable.
 * Unchecked low-level call with no return-value check and no gas safety
 * (Medium severity). Demonstrates a governance/relayer batching ETH.
 */
contract BatchPayout {
    address public owner;
    address[] public recipients;
    uint256[] public amounts;

    constructor() {
        owner = msg.sender;
    }

    // Sends ETH to many recipients. If one recipient is a contract that reverts
    // silently (or out-of-gas), the whole batch is marked dirty and others may
    // be paid inconsistently. No status check on each call.
    function payoutBatch() external {
        require(msg.sender == owner, "not owner");
        for (uint256 i = 0; i < recipients.length; i++) {
            // unchecked status; funds may be paid again or lost on retry
            recipients[i].call{value: amounts[i]}("");
        }
        delete recipients;
        delete amounts;
    }

    function setPayments(address[] calldata r, uint256[] calldata a) external {
        require(msg.sender == owner, "not owner");
        recipients = r;
        amounts = a;
    }
}
