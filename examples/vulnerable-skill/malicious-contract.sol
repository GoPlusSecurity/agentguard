// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * DEMO: Vulnerable Smart Contract
 *
 * This contract contains intentionally vulnerable patterns
 * for demonstrating GoPlus AgentGuard's Web3 security scanning.
 *
 * DO NOT deploy this contract. Every pattern here is a security risk.
 *
 * Run: /agentguard scan examples/vulnerable-skill
 */

contract VulnerableToken {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;
    address public owner;
    address public implementation;

    // --- WALLET_DRAINING: approve + transferFrom pattern ---
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount);
        allowance[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }

    // --- UNLIMITED_APPROVAL ---
    function approveMax(address spender) external {
        allowance[msg.sender][spender] = type(uint256).max;
    }

    // --- DANGEROUS_SELFDESTRUCT ---
    function destroy() external {
        require(msg.sender == owner);
        selfdestruct(payable(owner));
    }

    // --- HIDDEN_TRANSFER: Transfer in non-transfer function ---
    function updateBalance(address to, uint256 amount) internal {
        balances[msg.sender] -= amount;
        balances[to] += amount;  // Hidden transfer
    }

    // --- PROXY_UPGRADE ---
    bytes32 constant IMPLEMENTATION_SLOT = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    function upgradeTo(address newImplementation) external {
        require(msg.sender == owner);
        implementation = newImplementation;
    }

    // --- FLASH_LOAN_RISK ---
    function flashLoan(uint256 amount) external {
        uint256 balanceBefore = address(this).balance;
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        IFlashBorrower(msg.sender).executeOperation(amount);
        require(address(this).balance >= balanceBefore);
    }

    // --- REENTRANCY_PATTERN: External call before state change ---
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        // BUG: External call before state update
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;  // State change after external call
    }

    // --- SIGNATURE_REPLAY: ecrecover without nonce ---
    function verifySignature(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external pure returns (address) {
        return ecrecover(hash, v, r, s);
        // Missing: nonce tracking, domain separator, deadline
    }
}

interface IFlashBorrower {
    function executeOperation(uint256 amount) external;
}
