// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * EXAMPLE ONLY — intentionally vulnerable.
 * Demonstrates a classic reentrancy vulnerability (Critical severity).
 * Used by Smartsol as a demo/target for its AI-triage pipeline.
 */
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract ReentrancyVault {
    mapping(address => uint256) public balances;
    IERC20 public immutable token;

    // CEI not followed: state updated AFTER external call
    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        // external call before state update -> reentrancy
        (bool ok, ) = msg.sender.call{value: 0}("");
        require(ok, "call failed");
        require(token.transfer(msg.sender, amount), "transfer failed");
        balances[msg.sender] -= amount; // state updated last => vulnerable
    }

    // fallback allows malicious receiver to re-enter withdraw()
}
