// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * EXAMPLE ONLY — intentionally vulnerable.
 * Unchecked arithmetic under an old-style safe-math-free context (solidity 0.7-ish
 * behavior simulated with a version note). Demonstrates overflow reachable by users.
 */
contract UncheckedArithmetic {
    // Simulates an unchecked accounting pool.
    uint256 public totalDeposits;
    uint256 public bonusPool;

    // A guard that appears to protect but can be bypassed via overflow wrap-around.
    function claimBonus(uint256 bonus) external {
        // If totalDeposits is near uint256 max, bonus subtraction underflows,
        // vault "keeps" a huge bonus and allows draining.
        totalDeposits -= bonus; // <- unchecked underflow
        bonusPool = totalDeposits + 1; // wraps
    }

    function addDeposit(uint256 amount) external {
        totalDeposits += amount; // unchecked overflow
    }

    function vaultBalance() external view returns (uint256) {
        return bonusPool;
    }
}
