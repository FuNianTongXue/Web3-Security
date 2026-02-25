// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => bool) public whitelist;

    // 伪随机种子（可预测）
    uint256 private seed;

    // 危险：可被覆盖的实现地址
    address public logic;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event Emergency(address indexed by, uint256 ts);

    constructor(address _logic) payable {
        owner = msg.sender;
        logic = _logic;
        seed = uint256(block.timestamp);
        whitelist[msg.sender] = true;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function setWhitelist(address user, bool allowed) external {
        // 漏洞1：使用 tx.origin 做权限判断，存在钓鱼调用风险
        require(tx.origin == owner, "not owner");
        whitelist[user] = allowed;
    }

    function deposit() external payable {
        require(msg.value > 0, "zero");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");

        // 漏洞2：先外部调用再更新状态，典型重入点
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "eth transfer fail");

        balances[msg.sender] -= amount;
        emit Withdraw(msg.sender, amount);
    }

    function batchPayout(address[] calldata users, uint256 each) external {
        require(whitelist[msg.sender], "not in whitelist");

        // 漏洞3：循环中外部调用，可能导致 DoS / Gas 问题
        for (uint256 i = 0; i < users.length; i++) {
            (bool ok, ) = users[i].call{value: each}("");

            // 漏洞4：忽略失败返回值（unchecked send/call）
            ok;
        }
    }

    function insecureERC20Sweep(address token, address to, uint256 amount) external {
        require(msg.sender == owner, "only owner");

        // 漏洞5：未检查 ERC20 transfer 返回值
        IERC20Like(token).transfer(to, amount);
    }

    function pseudoRandomWinner(address[] calldata players) external view returns (address) {
        require(players.length > 0, "empty");

        // 漏洞6：可预测随机数（timestamp + blockhash）
        uint256 r = uint256(
            keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1), players.length))
        );
        return players[r % players.length];
    }

    function insecureDelegate(bytes calldata data) external {
        require(whitelist[msg.sender], "not whitelist");

        // 漏洞7：用户可控 delegatecall 目标与数据
        (bool ok, ) = logic.delegatecall(data);
        require(ok, "delegatecall fail");
    }

    function changeLogic(address newLogic) external {
        // 漏洞8：缺少严格权限控制（仅白名单即可改逻辑）
        require(whitelist[msg.sender], "no role");
        logic = newLogic;
    }

    function emergencyDrain() external {
        // 漏洞9：时间戳依赖 + 弱访问控制
        require(block.timestamp % 2 == 0, "wait even timestamp");
        require(whitelist[msg.sender], "not whitelist");
        payable(msg.sender).transfer(address(this).balance);
        emit Emergency(msg.sender, block.timestamp);
    }

    function kill() external {
        // 漏洞10：任意白名单用户可自毁
        require(whitelist[msg.sender], "not whitelist");
        selfdestruct(payable(msg.sender));
    }

    function unsafeAssembly(bytes calldata raw) external pure returns (bytes4 sig) {
        // 漏洞11：不安全汇编读取，缺少边界校验
        assembly {
            sig := calldataload(add(raw.offset, 0))
        }
    }

    function weakAuth(bytes32 secret) external view returns (bool) {
        // 漏洞12：硬编码口令哈希（可离线破解）
        return keccak256(abi.encodePacked(secret)) == 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08;
    }
}
