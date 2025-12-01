# EVM合约相似性分析 - pyevm二次开发需求文档

## 项目背景

对本repo ./pyevm.py 二次开发

### 原始需求：EVM合约相似性分析系统

我正在构建一个多层次的EVM合约相似性分析系统，包括：

1. **最严格层（成本最低）**：直接计算 `eth_getCode` 返回的 Deployed Code 的 MD5
2. **次严格层**：从 creation trace 的 input 中分离 init code 和构造参数，得到 runtime code template（构造函数执行前的字节码），计算 MD5
3. **中等宽松层**：反编译 runtime code 到 IR，针对每个函数计算 SimHash，使用 Hamming 距离比较相似性
4. **最宽松层**：提取 public function selectors 和 event topic0，基于签名相似性判断

**当前聚焦**：实现第2层 - 提取 runtime code template

### 核心挑战

从 creation bytecode（通过 `debug_traceTransaction` 获取）中提取 runtime code template 时，遇到的问题：

- **问题**：无法简单确定 runtime code 在 creation bytecode 中的起止位置
- **现有方案的缺陷**：
  - ❌ 方案1：正则匹配 CODECOPY - 不可靠，依赖假设（如没有跳转）
  - ⏳ 方案3：扩展 geth `debug_trace` - 已提交给同事，但需要等待
  - ✅ **方案2（当前选择）**：实现简易 EVM 执行器，执行到 CODECOPY 时捕获参数

## 知识背景（可能有用）

### zobront/pyevm 已经fork为本repo

**项目地址**: https://github.com/zobront/pyevm

**核心功能**：简易 EVM 实现，见 README

### 为什么选择在 CODECOPY 而不是 RETURN？
```
Creation Bytecode 结构：
├─ Init Code
│  ├─ 构造函数逻辑
│  ├─ CODECOPY (复制 runtime template 到内存)
│  ├─ 替换 immutable 占位符 (MSTORE)
│  └─ RETURN (返回修改后的 runtime code)
├─ Runtime Code Template (包含 0xFFFF...占位符)
└─ Constructor Arguments

选择 CODECOPY 的原因：
✅ 1. 获得的是 template（相同合约源码 → 相同 template）
✅ 2. 不需要执行完整构造函数（避免外部调用、storage 依赖）
✅ 3. 适合相似性分析（不同构造参数不影响判断）

如果在 RETURN：
❌ 获得的是 deployed code（immutable 已填充，不同构造参数 → 不同 hash）
❌ 需要完整的 state/block/storage 环境
❌ 可能因外部调用失败而无法完成
```

### EVM 内存模型
```
┌─────────────────────────────────────┐
│  Code (只读)                         │  ← creation bytecode 在这里
│  - CODECOPY 从这里读取               │
│  - 不可修改                          │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│  Memory (可读写)                     │  ← CODECOPY 复制到这里
│  - CODECOPY 的目标                   │
│  - MSTORE 在这里替换 immutable       │
└─────────────────────────────────────┘

关键理解：
- CODECOPY 将 Code 区域的数据复制到 Memory
- Immutable 替换发生在 Memory 中，不修改原始 Code
- RETURN 返回的是修改后的 Memory 内容
```

### CODECOPY 操作码细节
```
操作码：0x39
栈输入：[mem_offset, code_offset, length]
行为：Memory[mem_offset:mem_offset+length] = Code[code_offset:code_offset+length]

示例：
PUSH2 0x0400    // length = 1024
PUSH2 0x0100    // code_offset = 256  
PUSH1 0x40      // mem_offset = 64
CODECOPY        // Memory[64:1088] = Code[256:1280]

关键参数：
- code_offset: runtime template 在 creation bytecode 中的起始位置 ← 我们需要这个
- length: runtime template 的长度 ← 我们需要这个
```

### 为什么 CODECOPY 参数是静态的（编译时常量）
```solidity
// Solidity 编译器生成的 init code 模式（简化）
constructor(uint256 _value) {
    // 构造函数逻辑（可能包含外部调用）
    IERC20(token).approve(spender, amount);  // 外部调用
    owner = msg.sender;                       // 复杂计算
    
    // 但 CODECOPY 的参数永远是硬编码的
    PUSH2 0x0234    // ← 编译时确定的 offset
    PUSH1 0x00
    CODECOPY
    
    PUSH2 0x0234    // ← 编译时确定的 length
    PUSH1 0x00
    RETURN
}

原因：
✅ Runtime code 的大小在编译时就已确定
✅ 编译器总是生成静态的 PUSH 指令来加载这些参数
✅ 即使构造函数有复杂逻辑/外部调用，CODECOPY 参数也不会改变
```

### 合约创建的三种方式
```
方式1: EOA 直接部署
TX: { to: null, data: <init_code><runtime_template><constructor_args> }
└─ 通过 debug_traceTransaction 获取 input

方式2: 合约内 CREATE
CREATE(value, mem_offset, size)
└─ Trace 中显示为 CREATE call，input 就是 creation bytecode

方式3: 合约内 CREATE2  
CREATE2(value, mem_offset, size, salt)
└─ 同 CREATE，但地址计算不同

所有方式的 creation bytecode 结构相同，都能从 trace 获取
```

### Immutable 变量机制
```
Runtime Code Template（编译产物）：
PUSH32 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
       ↑ 这是 immutable 占位符

Init Code 流程：
1. CODECOPY: 复制 template 到 Memory[0x40]
2. 计算 immutable 值（如 block.number, msg.sender）
3. MSTORE: 在 Memory 中替换占位符
   Memory[0x40 + 0x123] = block.number
4. RETURN: 返回 Memory[0x40:...]

我们在 CODECOPY 时提取：
✅ 获得包含 0xFFFF 占位符的 template
✅ 相同源码的合约 → 相同 template
✅ 适合计算 hash 进行相似性比对
```

Immutable 变量布局 在Solidity/Vyper 编译器是不同的
```csv
特性,Solidity,Vyper
Template 结构,Code + 占位符 + Metadata,Code + Metadata
CODECOPY 长度,= Deployed size,< Deployed size
Immutable 位置,原地（占位符）,追加（末尾）
替换方式,Memory原地替换,Memory追加
长度关系,Template = Deployed,Template < Deployed
```

### 构造函数可以调用外部合约
```solidity
// 常见模式
contract Token {
    constructor(address registry) {
        IRegistry(registry).register(address(this));  // 外部调用
    }
}

对我们的影响：
✅ 简易 EVM 不需要处理外部调用
✅ 只需执行到 CODECOPY 即可（在外部调用之前或之后都无所谓）
✅ CODECOPY 参数是静态的，不受构造函数逻辑影响
```

## 当前 pyevm 实现分析

### 已实现的操作码（完整性评估）

---

## 操作码实现检查表（基于 evm.codes 规范）

> 检查日期：2025-11-27
> 参考规范：https://www.evm.codes/

### 状态说明
- ✅ 正确：实现符合规范，边界条件处理正确
- ⚠️ 简化：实现有简化，但对本项目需求足够
- ❌ 问题：存在已知问题
- 🚧 TODO：待实现

### 0x0* - 算术运算

| Opcode | 名称 | 状态 | 边界条件检查 | 备注 |
|--------|------|------|-------------|------|
| 0x00 | STOP | ✅ | N/A | 正确终止执行 |
| 0x01 | ADD | ✅ | 溢出 mod 2^256 | `overflower()` 处理 |
| 0x02 | MUL | ✅ | 溢出 mod 2^256 | `overflower()` 处理 |
| 0x03 | SUB | ✅ | 下溢 mod 2^256 | `overflower()` 处理负数 |
| 0x04 | DIV | ✅ | b=0 返回 0 | 已修复除零检查 |
| 0x05 | SDIV | ✅ | b=0 返回 0; -2^255/-1 返回 -2^255 | 向零截断；溢出边界已处理 |
| 0x06 | MOD | ✅ | b=0 返回 0 | 已修复除零检查 |
| 0x07 | SMOD | ✅ | b=0 返回 0; 符号跟随被除数 | 已修复符号处理 |
| 0x08 | ADDMOD | ✅ | N=0 返回 0; 先加后模避免溢出 | Python 大整数无溢出问题 |
| 0x09 | MULMOD | ✅ | N=0 返回 0 | Python 大整数无溢出问题 |
| 0x0A | EXP | ✅ | 使用 pow(a,b,2^256) | 三参数 pow 高效且正确 |
| 0x0B | SIGNEXTEND | ✅ | b>=31 原样返回 | 符号位扩展正确 |

### 0x1* - 比较和位运算

| Opcode | 名称 | 状态 | 边界条件检查 | 备注 |
|--------|------|------|-------------|------|
| 0x10 | LT | ✅ | 无符号比较 | 返回 0 或 1 |
| 0x11 | GT | ✅ | 无符号比较 | 返回 0 或 1 |
| 0x12 | SLT | ✅ | 有符号比较 | `twos_comp()` 转换 |
| 0x13 | SGT | ✅ | 有符号比较 | `twos_comp()` 转换 |
| 0x14 | EQ | ✅ | N/A | 返回 0 或 1 |
| 0x15 | ISZERO | ✅ | N/A | 返回 0 或 1 |
| 0x16 | AND | ✅ | N/A | 位与 |
| 0x17 | OR | ✅ | N/A | 位或 |
| 0x18 | XOR | ✅ | N/A | 位异或 |
| 0x19 | NOT | ✅ | 256位取反 | `overflower(~x)` |
| 0x1A | BYTE | ✅ | i>=32 返回 0 | 已修复边界条件 |
| 0x1B | SHL | ✅ | shift>=256 返回 0 | Constantinople |
| 0x1C | SHR | ✅ | shift>=256 返回 0 | Constantinople |
| 0x1D | SAR | ✅ | shift>=256 返回 0/-1 | 负数算术右移填充1 |

### 0x20 - Keccak256

| Opcode | 名称 | 状态 | 边界条件检查 | 备注 |
|--------|------|------|-------------|------|
| 0x20 | SHA3/KECCAK256 | ✅ | size=0 时 hash 空串 | 使用 eth_hash 库 |

### 0x3* - 环境信息

| Opcode | 名称 | 状态 | 边界条件检查 | 备注 |
|--------|------|------|-------------|------|
| 0x30 | ADDRESS | ✅ | tx.to 缺失返回 0 | |
| 0x31 | BALANCE | ✅ | 地址不存在返回 0 | |
| 0x32 | ORIGIN | ✅ | tx.origin 缺失返回 0 | |
| 0x33 | CALLER | ✅ | tx.from 缺失返回 0 | |
| 0x34 | CALLVALUE | ✅ | 支持 int 和 hex string | |
| 0x35 | CALLDATALOAD | ✅ | 越界填充 0 | `ljust(32, b'\x00')` |
| 0x36 | CALLDATASIZE | ✅ | 空 data 返回 0 | |
| 0x37 | CALLDATACOPY | ✅ | 越界填充 0 | |
| 0x38 | CODESIZE | ✅ | N/A | |
| 0x39 | CODECOPY | ✅ | 越界填充 0; 记录到 codecopy_logs | 核心功能 |
| 0x3A | GASPRICE | ✅ | 支持 int 和 hex string | |
| 0x3B | EXTCODESIZE | ✅ | 地址不存在返回 0 | |
| 0x3C | EXTCODECOPY | ✅ | 越界填充 0 | |
| 0x3D | RETURNDATASIZE | ✅ | 初始为 0 | Byzantium |
| 0x3E | RETURNDATACOPY | ✅ | 越界抛异常 (EIP-211) | 与其他 COPY 不同 |
| 0x3F | EXTCODEHASH | ✅ | 空账户返回 0 | Constantinople |

### 0x4* - 区块信息

| Opcode | 名称 | 状态 | 边界条件检查 | 备注 |
|--------|------|------|-------------|------|
| 0x40 | BLOCKHASH | ⚠️ | mock 实现 | 返回 keccak256(blockNumber)，非真实链上值 |
| 0x41 | COINBASE | ✅ | 缺失返回 0 | |
| 0x42 | TIMESTAMP | ✅ | 支持 int 和 hex string | |
| 0x43 | NUMBER | ✅ | 支持 int 和 hex string | |
| 0x44 | DIFFICULTY/PREVRANDAO | ✅ | 支持 int 和 hex string | Merge 后为 PREVRANDAO |
| 0x45 | GASLIMIT | ✅ | 支持 int 和 hex string | |
| 0x46 | CHAINID | ✅ | 支持 int 和 hex string | Istanbul |
| 0x47 | SELFBALANCE | ✅ | 地址不存在返回 0 | Istanbul |
| 0x48 | BASEFEE | ✅ | 支持 int 和 hex string | London |

### 0x5* - 栈/内存/存储/控制流

| Opcode | 名称 | 状态 | 边界条件检查 | 备注 |
|--------|------|------|-------------|------|
| 0x50 | POP | ✅ | 栈下溢由 deque 抛异常 | |
| 0x51 | MLOAD | ✅ | 未初始化返回 0 | |
| 0x52 | MSTORE | ✅ | 256位大端存储 | |
| 0x53 | MSTORE8 | ✅ | 取最低字节 | `& 0xFF` |
| 0x54 | SLOAD | ✅ | 未初始化返回 0 | |
| 0x55 | SSTORE | ✅ | N/A | 不跟踪 gas refund |
| 0x56 | JUMP | ✅ | 目标必须是 JUMPDEST | 已修复验证逻辑 |
| 0x57 | JUMPI | ✅ | condition!=0 则跳转 | 已修复验证逻辑 |
| 0x58 | PC | ✅ | 返回当前指令位置 | 已修复 cursor-1 |
| 0x59 | MSIZE | ✅ | 32字节对齐 | |
| 0x5A | GAS | ⚠️ | 返回大值 | 不跟踪 gas |
| 0x5B | JUMPDEST | ✅ | 无操作 | |
| 0x5F | PUSH0 | ✅ | N/A | Shanghai |

### 0x6*-0x7* - PUSH 指令

| Opcode | 名称 | 状态 | 边界条件检查 | 备注 |
|--------|------|------|-------------|------|
| 0x60-0x7F | PUSH1-PUSH32 | ✅ | code 末尾不足则填 0 | 已修复 cursor += N |

### 0x8*-0x9* - DUP/SWAP 指令

| Opcode | 名称 | 状态 | 边界条件检查 | 备注 |
|--------|------|------|-------------|------|
| 0x80-0x8F | DUP1-DUP16 | ✅ | 栈深度不足由 deque 抛异常 | |
| 0x90-0x9F | SWAP1-SWAP16 | ✅ | 栈深度不足由 deque 抛异常 | |

### 0xA* - LOG 指令

| Opcode | 名称 | 状态 | 边界条件检查 | 备注 |
|--------|------|------|-------------|------|
| 0xA0-0xA4 | LOG0-LOG4 | ✅ | 记录到 events 列表 | |

### 0xF* - 系统操作

| Opcode | 名称 | 状态 | 边界条件检查 | 备注 |
|--------|------|------|-------------|------|
| 0xF0 | CREATE | ⚠️ | 简化地址计算 | 未正确实现 nonce |
| 0xF1 | CALL | ⚠️ | 空合约返回成功 | 支持 mock 模式 |
| 0xF2 | CALLCODE | ✅ | 在当前上下文执行目标代码 | msg.sender=this, msg.value=参数; 已废弃，推荐 DELEGATECALL |
| 0xF3 | RETURN | ✅ | N/A | |
| 0xF4 | DELEGATECALL | ✅ | 在当前上下文执行目标代码 | 保留原始 msg.sender 和 msg.value |
| 0xF5 | CREATE2 | ⚠️ | 返回占位地址 | 简化实现 |
| 0xFA | STATICCALL | ✅ | 不允许状态修改 | 未强制检查 |
| 0xFD | REVERT | ✅ | success=False | |
| 0xFE | INVALID | ✅ | success=False | |
| 0xFF | SELFDESTRUCT | ⚠️ | 仅消费参数 | Cancun 后行为变化 |

### 已发现并修复的问题

| 问题 | 位置 | 修复内容 |
|------|------|----------|
| DIV/SDIV/MOD/SMOD 除零检查 | :74,:79,:84,:89 | `if a != 0` → `if b != 0` |
| SDIV 向零截断和溢出边界 | :77-91 | 处理 -2^255/-1 边界；使用 abs() 实现向零截断 |
| SMOD 符号处理 | :98-109 | 结果符号跟随被除数 |
| JUMP/JUMPI 验证 | :400,:407 | `stack[0] == 0x5b` → `code[cursor] == 0x5b` |
| PUSH1-PUSH32 cursor | :428 | 添加 `cursor += N` |
| PC 返回值 | :411 | `cursor` → `cursor - 1` |
| BYTE 边界 | :188 | `i > 32` → `i >= 32` |
| *COPY 内存计算 | 多处 | `offset + size` → `dest + size` |
| CALLVALUE 类型 | :245-248 | 支持整数类型 |

### 未实现的操作码

以下操作码遇到时会抛出 `Exception("Unsupported opcode: 0x...")`：

- 预编译合约调用 (0x01-0x0A 地址)

### 简化实现的操作码

- 0x40 BLOCKHASH: 返回 mock 值 (基于 block number 的 keccak256)

## 实现建议

### 核心功能：提取 runtime code template

修改 pyevm.py 函数 evm(code, state, block, tx)
原先的返回值是 return_obj, stack
return_obj 中原有2个字段 success:bool, return:any
再给我新增一个可选字段 codecopy_logs:list 每个元素就是3个参数的元组 (dest,offset,size)
再给我新增一个可选字段 events:list

### 边界情况处理
```
# 1. 多个 CODECOPY
#    策略：返回所有 CODECOPY，让调用者选择
#    调用者自己需了解，通常第一个是 runtime code，后续可能是库代码

# 2. 跳转到 CODECOPY（JUMP/JUMPI）
#    策略：正常执行控制流，直到遇到 CODECOPY
#    pyevm 已实现 JUMP/JUMPI，无需特殊处理

# 3. 外部调用失败
#    策略：mock 所有外部调用返回成功
#    CALL/DELEGATECALL/STATICCALL
#    evm(code, state, block, tx, external_call_always_success=False) 调用方自己设 true

# 4. 缺失的操作码
#    策略：补全高频操作码，其他遇到时抛异常并记录
#    现代操作码全列表可以参考 https://www.evm.codes/
```

### 测试用例

大部分测试用例在 ./evm.json
先把那个 ./evm.json 的测试给通过
再考虑额外的测试用例：

```python
test_cases = [
    {
        "name": "simple_contract",
        "creation_bytecode": "608060405234801561001057600080fd5b50...",
        "expected": {
            "code_offset": 256,
            "length": 1024,
        }
    },
    {
        "name": "with_immutable",
        "creation_bytecode": "...",
        "expected": {
            "runtime_template": "...FFFFFFFFFFFFFFFF...",  # 包含占位符
        }
    },
    {
        "name": "with_external_call_in_constructor",
        "creation_bytecode": "...",
        "expected": {
            "code_offset": 512,  # 外部调用不影响 CODECOPY 参数
        }
    }
]
```

## 代码风格

原版代码具有老Python风格
二次开发时应当遵循现代Python风格 3.8 ~ 3.14
next_inst 可以保留int，但每次分支时，== 后面改成 0x形式的 int 字面量，并加上操作码的名称和参数注释，例如：
```
    ...
elif next_inst == 0x39:  # CODECOPY destOffset offset size
    ...
```

## 开发清单

- [x] 理解现有实现
- [x] 添加 CODECOPY 捕获机制（codecopy_logs的函数内全局变量）
- [x] 补全缺失的高频操作码（EXP, SHL, SHR, SAR）
- [x] 标记缺失的非高频操作码，抛出裸 Exception(msg)
- [x] 添加参数允许 Mock CALL 系列调用成功返回
- [x] 实现 CALLCODE (0xF2) - 在当前上下文执行目标代码，msg.sender=this
- [x] 实现 DELEGATECALL (0xF4) - 在当前上下文执行目标代码，保留原始 caller/value
- [x] 实现 BLOCKHASH (0x40) - mock 实现，返回基于 block number 的 keccak256
- [ ] 添加测试用例（简单合约、带 immutable、带外部调用）

## 参考资料

- EVM Opcodes: https://www.evm.codes/
- Yellow Paper: https://ethereum.github.io/yellowpaper/paper.pdf
- Solidity 编译器输出格式: https://docs.soliditylang.org/en/latest/using-the-compiler.html
- zobront/pyevm 原仓库: https://github.com/zobront/pyevm
