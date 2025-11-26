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

**✅ 对我们的需求足够的部分**：
- `0x01-0x07`: 算术运算（ADD, MUL, SUB, DIV, SDIV, MOD, SMOD）
- `0x10-0x1A`: 比较和位运算（LT, GT, EQ, AND, OR, XOR, NOT, BYTE）
- `0x39`: **CODECOPY** ✅ - 核心需求
- `0x50`: POP
- `0x51-0x55`: 内存/存储操作（MLOAD, MSTORE, MSTORE8, SLOAD, SSTORE）
- `0x56-0x57`: **JUMP, JUMPI** ✅ - 控制流必需
- `0x60-0x7F`: **PUSH1-PUSH32** ✅ - 加载 CODECOPY 参数
- `0x80-0x8F`: **DUP1-DUP16** ✅ - 栈操作
- `0x90-0x9F`: **SWAP1-SWAP16** ✅ - 栈操作
- `0xF3`: RETURN

**❌ 缺失但对构造函数可能重要的**：
- `0x0A`: EXP - 指数运算（较常用）
- `0x08-0x09`: ADDMOD, MULMOD - 模运算
- `0x1B-0x1D`: SHL, SHR, SAR - 位移操作（Constantinople 2019）
- `0x3D-0x3E`: RETURNDATASIZE, RETURNDATACOPY - 外部调用返回值（Byzantium 2017）
- `0x5F`: PUSH0 - （Shanghai 2023）

**❌ 缺失但构造函数很少用的**：
- `0xF0, 0xF5`: CREATE, CREATE2
- `0xF1, 0xF2, 0xF4, 0xFA`: CALL 系列
- `0xA0-0xA4`: LOG0-LOG4

### 需要补全的操作码（优先级排序）

**优先级 1 - 高频且影响执行**：
```
0x0A: EXP          # 指数运算，某些合约会用
0x1B: SHL          # 左移，优化代码常用
0x1C: SHR          # 右移
0x1D: SAR          # 算术右移
```

**优先级 2 - 外部调用相关（可简化处理）**：
```
0x3D: RETURNDATASIZE    # 外部调用后获取返回数据大小
0x3E: RETURNDATACOPY    # 复制返回数据
0xF1: CALL              # 外部调用（可 mock 返回成功）
0xF4: DELEGATECALL      # 代理调用（可 mock）
0xFA: STATICCALL        # 静态调用（可 mock）
```

**优先级 3 - 新硬分叉（增强兼容性）**：
```
0x5F: PUSH0        # Shanghai 2023
0x48: BASEFEE      # London 2021
```

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

- [ ] 理解现有实现
- [ ] 添加 CODECOPY 捕获机制（codecopy_logs的函数内全局变量）
- [ ] 补全缺失的高频操作码（EXP, SHL, SHR, SAR）
- [ ] 标记缺失的非高频操作码，抛出裸 Exception(msg)
- [ ] 添加参数允许 Mock CALL 系列调用成功返回
- [ ] 添加测试用例（简单合约、带 immutable、带外部调用）

## 参考资料

- EVM Opcodes: https://www.evm.codes/
- Yellow Paper: https://ethereum.github.io/yellowpaper/paper.pdf
- Solidity 编译器输出格式: https://docs.soliditylang.org/en/latest/using-the-compiler.html
- zobront/pyevm 原仓库: https://github.com/zobront/pyevm
