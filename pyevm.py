import json
import math
import collections
from typing import Any

from eth_hash.auto import keccak


def evm(
        code: bytes,
        state: dict,
        block: dict,
        tx: dict,
        external_call_always_success: bool = False,
) -> tuple[dict[str, Any], list[int]]:
    """
    Execute EVM bytecode.

    Args:
        code: The bytecode to execute
        state: World state (account balances, code, storage)
        block: Block context (number, timestamp, etc.)
        tx: Transaction context (from, to, value, data, etc.)
        external_call_always_success: If True, mock all external calls to return success

    Returns:
        tuple of (return_obj, stack) where return_obj contains:
            - success: "true" or "false"
            - return: hex string of return data
            - codecopy_logs: list of (dest_offset, code_offset, size, _code, _addr) tuples
            - events: list of event logs
    """

    stack: collections.deque[int] = collections.deque()
    memory: dict[int, int] = {}
    storage: dict[int, int] = {}
    if tx.get("to") in state:
        storage = {int(k): int(v) for k, v in state.get(tx["to"], {}).get("storage", {}).items()}  # TODO
    return_data: bytes = b""  # For RETURNDATASIZE/RETURNDATACOPY

    highest_accessed_memory = 0
    codecopy_logs: list[tuple[int, int, int, bytes, str]] = []
    events: list[dict] = []

    return_obj = {'highest_accessed_memory': highest_accessed_memory,
                  'codecopy_logs': codecopy_logs,
                  'events': events}
    # return_obj['success'] = ...
    # return_obj['return'] = ...

    cursor = 0
    while cursor < len(code):
        next_inst = int(code[cursor])
        cursor += 1

        if next_inst == 0x00:  # STOP
            # storage = copy.deepcopy(state.get(contract_addr, {}).get("storage", {}))  # revert?
            return return_obj, list(stack)

        elif next_inst == 0x01:  # ADD a b
            result = overflower(stack.popleft() + stack.popleft())
            stack.appendleft(result)

        elif next_inst == 0x02:  # MUL a b
            result = overflower(stack.popleft() * stack.popleft())
            stack.appendleft(result)

        elif next_inst == 0x03:  # SUB a b
            result = overflower(stack.popleft() - stack.popleft())
            stack.appendleft(result)

        elif next_inst == 0x04:  # DIV a b
            a, b = stack.popleft(), stack.popleft()
            result = overflower(a // b) if b != 0 else 0
            stack.appendleft(result)

        elif next_inst == 0x05:  # SDIV a b
            a, b = stack.popleft(), stack.popleft()
            if b == 0:
                result = 0
            else:
                sa, sb = twos_comp(a), twos_comp(b)
                # Special case: -2^255 / -1 = -2^255 (overflow, cannot represent 2^255)
                INT_MIN = -(2 ** 255)
                if sa == INT_MIN and sb == -1:
                    result = a  # Return original a (which is 2^255 in unsigned = -2^255 in signed)
                else:
                    # Truncate toward zero (Python // rounds toward -inf, need to adjust)
                    sign = -1 if (sa < 0) != (sb < 0) else 1
                    result = overflower(sign * (abs(sa) // abs(sb)))
            stack.appendleft(result)

        elif next_inst == 0x06:  # MOD a b
            a, b = stack.popleft(), stack.popleft()
            result = overflower(a % b) if b != 0 else 0
            stack.appendleft(result)

        elif next_inst == 0x07:  # SMOD a b
            a, b = stack.popleft(), stack.popleft()
            if b == 0:
                result = 0
            else:
                sa, sb = twos_comp(a), twos_comp(b)
                # Result sign follows dividend (sa), use abs for calculation
                mod_result = abs(sa) % abs(sb)
                if sa < 0:
                    mod_result = -mod_result
                result = overflower(mod_result)
            stack.appendleft(result)

        elif next_inst == 0x08:  # ADDMOD a b N
            a, b, N = stack.popleft(), stack.popleft(), stack.popleft()
            result = (a + b) % N if N != 0 else 0
            stack.appendleft(result)

        elif next_inst == 0x09:  # MULMOD a b N
            a, b, N = stack.popleft(), stack.popleft(), stack.popleft()
            result = (a * b) % N if N != 0 else 0
            stack.appendleft(result)

        elif next_inst == 0x0A:  # EXP a exponent
            base, exponent = stack.popleft(), stack.popleft()
            result = overflower(pow(base, exponent, 2 ** 256))
            stack.appendleft(result)

        elif next_inst == 0x0B:  # SIGNEXTEND b x
            b, x = stack.popleft(), stack.popleft()
            if b < 31:
                sign_bit = 1 << (8 * b + 7)
                mask = sign_bit - 1
                if x & sign_bit:
                    result = x | ~mask
                    result = overflower(result)
                else:
                    result = x & mask
            else:
                result = x
            stack.appendleft(result)

        elif next_inst == 0x10:  # LT a b
            a, b = stack.popleft(), stack.popleft()
            result = int(a < b)
            stack.appendleft(result)

        elif next_inst == 0x11:  # GT a b
            a, b = stack.popleft(), stack.popleft()
            result = int(a > b)
            stack.appendleft(result)

        elif next_inst == 0x12:  # SLT a b
            a, b = stack.popleft(), stack.popleft()
            result = int(twos_comp(a) < twos_comp(b))
            stack.appendleft(result)

        elif next_inst == 0x13:  # SGT a b
            a, b = stack.popleft(), stack.popleft()
            result = int(twos_comp(a) > twos_comp(b))
            stack.appendleft(result)

        elif next_inst == 0x14:  # EQ a b
            a, b = stack.popleft(), stack.popleft()
            result = int(a == b)
            stack.appendleft(result)

        elif next_inst == 0x15:  # ISZERO a
            a = stack.popleft()
            result = int(a == 0)
            stack.appendleft(result)

        elif next_inst == 0x16:  # AND a b
            result = stack.popleft() & stack.popleft()
            stack.appendleft(result)

        elif next_inst == 0x17:  # OR a b
            result = stack.popleft() | stack.popleft()
            stack.appendleft(result)

        elif next_inst == 0x18:  # XOR a b
            result = stack.popleft() ^ stack.popleft()
            stack.appendleft(result)

        elif next_inst == 0x19:  # NOT a
            result = overflower(~stack.popleft())
            stack.appendleft(result)

        elif next_inst == 0x1A:  # BYTE i x
            i, x = stack.popleft(), stack.popleft()
            if i >= 32:
                result = 0
            else:
                result = (x >> (248 - (8 * i))) & 0xFF
            stack.appendleft(result)

        elif next_inst == 0x1B:  # SHL shift value
            shift, value = stack.popleft(), stack.popleft()
            if shift >= 256:
                result = 0
            else:
                result = overflower(value << shift)
            stack.appendleft(result)

        elif next_inst == 0x1C:  # SHR shift value
            shift, value = stack.popleft(), stack.popleft()
            if shift >= 256:
                result = 0
            else:
                result = value >> shift
            stack.appendleft(result)

        elif next_inst == 0x1D:  # SAR shift value
            shift, value = stack.popleft(), stack.popleft()
            signed_value = twos_comp(value)
            if shift >= 256:
                result = 0 if signed_value >= 0 else overflower(-1)
            else:
                result = overflower(signed_value >> shift)
            stack.appendleft(result)

        elif next_inst == 0x20:  # SHA3 offset size (actually KECCAK256)
            offset, size = stack.popleft(), stack.popleft()
            data = bytes([memory.get(i, 0) for i in range(offset, offset + size)])
            if offset + size > highest_accessed_memory:
                highest_accessed_memory = math.ceil((offset + size) / 32) * 32
            result = int.from_bytes(keccak(data), "big")
            stack.appendleft(result)

        elif next_inst == 0x30:  # ADDRESS
            result = int(tx.get("to", "0x0"), 16)
            stack.appendleft(result)

        elif next_inst == 0x31:  # BALANCE addr
            addr_int = stack.popleft()
            address = "0x" + hex(addr_int)[2:].zfill(40)
            result = int(state.get(address, {}).get("balance", 0))
            stack.appendleft(result)

        elif next_inst == 0x32:  # ORIGIN
            result = int(tx.get("origin", "0x0"), 16)
            stack.appendleft(result)

        elif next_inst == 0x33:  # CALLER
            result = int(tx.get("from", "0x0"), 16)
            stack.appendleft(result)

        elif next_inst == 0x34:  # CALLVALUE
            value = tx.get("value", "0x0")
            result = value if isinstance(value, int) and value >= 0 else int(value, 16)
            stack.appendleft(result)

        elif next_inst == 0x35:  # CALLDATALOAD i
            i = stack.popleft()
            data = bytes.fromhex(tx.get("data", "").replace("0x", ""))
            data_slice = data[i:].ljust(32, b'\x00')[:32]
            result = int.from_bytes(data_slice, "big")
            stack.appendleft(result)

        elif next_inst == 0x36:  # CALLDATASIZE
            data = bytes.fromhex(tx.get("data", "").replace("0x", ""))
            stack.appendleft(len(data))

        elif next_inst == 0x37:  # CALLDATACOPY destOffset offset size
            dest, offset, size = stack.popleft(), stack.popleft(), stack.popleft()
            data = bytes.fromhex(tx.get("data", "").replace("0x", ""))
            value = data[offset: offset + size].ljust(size, b'\x00')
            for i, b in enumerate(value):
                memory[dest + i] = b
            if dest + size > highest_accessed_memory:
                highest_accessed_memory = math.ceil((dest + size) / 32) * 32

        elif next_inst == 0x38:  # CODESIZE
            stack.appendleft(len(code))

        elif next_inst == 0x39:  # CODECOPY destOffset offset size
            dest, offset, size = stack.popleft(), stack.popleft(), stack.popleft()
            value = code[offset: offset + size].ljust(size, b'\x00')
            for i, b in enumerate(value):
                memory[dest + i] = b
            if dest + size > highest_accessed_memory:
                highest_accessed_memory = math.ceil((dest + size) / 32) * 32

            this_addr_int = int(tx.get("to", "0x0"), 16)
            this_addr = "0x" + this_addr_int.to_bytes(20, "big").hex()

            codecopy_logs.append((dest, offset, size, code, this_addr))

        elif next_inst == 0x40:  # BLOCKHASH blockNumber
            block_height = stack.popleft()
            # Mock
            mocked_block_hash = int.from_bytes(keccak(block_height.to_bytes(32, 'big')), "big")
            print('Warning', 'BLOCKHASH', block_height, '=>', '<mocked_block_hash>')
            stack.appendleft(mocked_block_hash)

        elif next_inst == 0x3A:  # GASPRICE
            gasprice = tx.get("gasprice", "0x0")
            result = gasprice if isinstance(gasprice, int) and gasprice >= 0 else int(gasprice.replace("0x", ""), 16)
            stack.appendleft(result)

        elif next_inst == 0x3B:  # EXTCODESIZE addr
            addr_int = stack.popleft()
            address = "0x" + hex(addr_int)[2:].zfill(40)
            extcode = bytes.fromhex(state.get(address, {}).get("code", {}).get("bin", "").replace("0x", ""))
            stack.appendleft(len(extcode))

        elif next_inst == 0x3C:  # EXTCODECOPY addr destOffset codeOffset size
            addr_int, dest, offset, size = stack.popleft(), stack.popleft(), stack.popleft(), stack.popleft()
            address = "0x" + hex(addr_int)[2:].zfill(40)
            extcode = bytes.fromhex(state.get(address, {}).get("code", {}).get("bin", "").replace("0x", ""))
            value = extcode[offset:offset + size].ljust(size, b'\x00')
            for i, b in enumerate(value):
                memory[dest + i] = b
            if dest + size > highest_accessed_memory:
                highest_accessed_memory = math.ceil((dest + size) / 32) * 32

        elif next_inst == 0x3D:  # RETURNDATASIZE
            stack.appendleft(len(return_data))

        elif next_inst == 0x3E:  # RETURNDATACOPY destOffset offset size
            dest, offset, size = stack.popleft(), stack.popleft(), stack.popleft()
            if offset + size > len(return_data):
                raise Exception('offset + size is larger than RETURNDATASIZE. (forks <EOF)')
            value = return_data[offset:offset + size].ljust(size, b'\x00')
            for i, b in enumerate(value):
                memory[dest + i] = b
            if dest + size > highest_accessed_memory:
                highest_accessed_memory = math.ceil((dest + size) / 32) * 32

        elif next_inst == 0x3F:  # EXTCODEHASH addr
            addr_int = stack.popleft()
            address = "0x" + hex(addr_int)[2:].zfill(40)
            extcode = bytes.fromhex(state.get(address, {}).get("code", {}).get("bin", "").replace("0x", ""))
            if extcode:
                result = int.from_bytes(keccak(extcode), "big")
            else:
                result = 0
            stack.appendleft(result)

        elif next_inst == 0x41:  # COINBASE
            result = int(block.get("coinbase", '0x0'), 16)
            stack.appendleft(result)

        elif next_inst == 0x42:  # TIMESTAMP
            timestamp = block.get("timestamp", "0x0")
            result = timestamp if isinstance(timestamp, int) and timestamp >= 0 else int(timestamp, 16)
            stack.appendleft(result)

        elif next_inst == 0x43:  # NUMBER
            number = block.get("number", "0x0")
            result = number if isinstance(number, int) and number >= 0 else int(number, 16)
            stack.appendleft(result)

        elif next_inst == 0x44:  # DIFFICULTY (PREVRANDAO after merge)
            difficulty = block.get("difficulty", "0x0")
            result = difficulty if isinstance(difficulty, int) and difficulty >= 0 else int(difficulty, 16)
            stack.appendleft(result)

        elif next_inst == 0x45:  # GASLIMIT
            gaslimit = block.get("gaslimit", "0x0")
            result = gaslimit if isinstance(gaslimit, int) and gaslimit >= 0 else int(gaslimit, 16)
            stack.appendleft(result)

        elif next_inst == 0x46:  # CHAINID
            chainid = block.get("chainid", "0x0")
            result = chainid if isinstance(chainid, int) and chainid >= 0 else int(chainid, 16)
            stack.appendleft(result)

        elif next_inst == 0x47:  # SELFBALANCE
            addr_int = int(tx.get("to", "0x0"), 16)
            address = "0x" + hex(addr_int)[2:].zfill(40)
            stack.appendleft(int(state.get(address, {}).get("balance", 0)))

        elif next_inst == 0x48:  # BASEFEE (London 2021)
            basefee = block.get("basefee", "0x0")
            result = basefee if isinstance(basefee, int) and basefee >= 0 else int(basefee, 16)
            stack.appendleft(result)

        elif next_inst == 0x50:  # POP
            stack.popleft()

        elif next_inst == 0x51:  # MLOAD offset
            offset = stack.popleft()
            value = bytes([memory.get(i, 0) for i in range(offset, offset + 32)])
            if offset + 32 > highest_accessed_memory:
                highest_accessed_memory = math.ceil((offset + 32) / 32) * 32
            result = int.from_bytes(value, "big")
            stack.appendleft(result)

        elif next_inst == 0x52:  # MSTORE offset value
            offset, value_int = stack.popleft(), stack.popleft()
            value_hex = hex(value_int)[2:].rjust(64, "0")
            value = bytes.fromhex(value_hex)
            for i, b in enumerate(value):
                memory[offset + i] = b
            if offset + 32 > highest_accessed_memory:
                highest_accessed_memory = math.ceil((offset + 32) / 32) * 32

        elif next_inst == 0x53:  # MSTORE8 offset value
            offset, value_int = stack.popleft(), stack.popleft()
            memory[offset] = value_int & 0xFF
            if offset > highest_accessed_memory:
                highest_accessed_memory = math.ceil(offset / 32) * 32

        elif next_inst == 0x54:  # SLOAD key
            key = stack.popleft()
            value = int(storage.get(key, 0))
            stack.appendleft(value)

        elif next_inst == 0x55:  # SSTORE key value
            key, value = stack.popleft(), stack.popleft()
            storage[key] = value

        elif next_inst == 0x56:  # JUMP dest
            dest = stack.popleft()
            cursor = dest
            assert code[cursor] == 0x5b, f"Invalid JUMP destination: {dest}"

        elif next_inst == 0x57:  # JUMPI dest condition
            dest, condition = stack.popleft(), stack.popleft()
            if condition > 0:
                cursor = dest
                assert code[cursor] == 0x5b, f"Invalid JUMPI destination: {dest}"

        elif next_inst == 0x58:  # PC
            stack.appendleft(cursor - 1)  # cursor already advanced past this opcode

        elif next_inst == 0x59:  # MSIZE
            stack.appendleft(highest_accessed_memory)

        elif next_inst == 0x5A:  # GAS
            print('Warning', 'GAS', '=>', '<infinity_gas>', "Return large value as we don't track gas")
            stack.appendleft(0xffffffffffffffffffffffffffffffffffffffff)  # Return large value as we don't track gas

        elif next_inst == 0x5B:  # JUMPDEST
            pass  # No operation, just a valid jump destination marker

        elif next_inst == 0x5F:  # PUSH0 (Shanghai 2023)
            stack.appendleft(0)

        elif 0x60 <= next_inst <= 0x7F:  # PUSH1-PUSH32
            N = next_inst - 0x60 + 1
            stack.appendleft(int.from_bytes(code[cursor:cursor + N], "big"))
            cursor += N

        elif 0x80 <= next_inst <= 0x8F:  # DUP1-DUP16
            pos = next_inst - 0x80
            stack.appendleft(stack[pos])

        elif 0x90 <= next_inst <= 0x9F:  # SWAP1-SWAP16
            pos = next_inst - 0x90 + 1
            stack[0], stack[pos] = stack[pos], stack[0]

        elif 0xA0 <= next_inst <= 0xA4:  # LOG0-LOG4
            num_topics = next_inst - 0xA0
            offset, size = stack.popleft(), stack.popleft()
            topics = [stack.popleft() for _ in range(num_topics)]
            log_data = bytes([memory.get(offset + i, 0) for i in range(size)])
            this_addr_int = int(tx.get("to", "0x0"), 16)
            this_addr = "0x" + this_addr_int.to_bytes(20, "big").hex()
            events.append({
                "topics": ["0x" + hex(t)[2:].zfill(64) for t in topics],
                "data": log_data.hex(),
                "address": this_addr,
            })

        elif next_inst in (0xF0, 0xF5):  # CREATE / CREATE2
            if next_inst == 0xF0:
                # CREATE value offset size
                create_value, offset, size = stack.popleft(), stack.popleft(), stack.popleft()
                # Get init code from memory
                init_code = bytes([memory.get(offset + i, 0) for i in range(size)])

                # Compute contract address: keccak256(rlp([sender, nonce]))[12:]
                # Simplified: use a deterministic address based on sender
                creator_int = int(tx.get("to", "0x0"), 16)
                creator = "0x" + creator_int.to_bytes(20, "big").hex()
                # Simple nonce tracking via a counter based on code position
                nonce = 0
                print('Warning', 'CREATE', 'always nonce=0')
                addr_preimage = creator_int.to_bytes(20, "big") + nonce.to_bytes(8, "big")
                new_addr = "0x" + keccak(addr_preimage)[-20:].hex()
            else:
                # CREATE2 value offset size salt
                create_value, offset, size, salt = stack.popleft(), stack.popleft(), stack.popleft(), stack.popleft()
                init_code = bytes([memory.get(offset + i, 0) for i in range(size)])

                creator_int = int(tx.get("to", "0x0"), 16)
                creator = "0x" + creator_int.to_bytes(20, "big").hex()
                # CREATE2 address formula
                # address = keccak256(0xff ++ sender_address ++ salt ++ keccak256(init_code))[12:]
                prefix = bytes([0xff])
                sender_bytes = creator_int.to_bytes(20, "big")
                salt_bytes = salt.to_bytes(32, "big")
                init_code_hash = keccak(init_code)
                addr_preimage = prefix + sender_bytes + salt_bytes + init_code_hash
                new_addr = "0x" + keccak(addr_preimage)[-20:].hex()

            # Execute init code to get runtime code
            if init_code:
                new_tx = {
                    "from": creator,
                    "to": new_addr,
                    "value": create_value,
                }
                return_value, _ = evm(init_code, state, block, new_tx, external_call_always_success)
                runtime_code = return_value.get("return", "")
                success = return_value.get("success", False)
                codecopy_logs.extend(return_value.get("codecopy_logs", []))
                events.extend(return_value.get("events", []))

                if success:
                    # Store the new contract in state
                    state[new_addr] = {
                        "balance": create_value,
                        "code": {"bin": runtime_code},
                    }
                    result = int(new_addr, 16)
                else:
                    result = 0
            else:
                # Empty init code, just create an account with the value
                state[new_addr] = {
                    "balance": create_value,
                    "code": {"bin": ""},
                }
                result = int(new_addr, 16)

            stack.appendleft(result)

        elif next_inst == 0xF1:  # CALL gas addr value argsOffset argsSize retOffset retSize
            gas, addr_int, value, argsOffset, argsSize, retOffset, retSize = [stack.popleft() for _ in range(7)]

            address = "0x" + addr_int.to_bytes(20, "big").hex()
            this_addr_int = int(tx.get("to", "0x0"), 16)
            this_address = "0x" + this_addr_int.to_bytes(20, "big").hex()

            calldata = bytes([memory.get(pos, 0) for pos in range(argsOffset, argsOffset + argsSize)])  # 4bytes-selector + call-args

            calling_code = bytes.fromhex(state.get(address, {}).get("code", {}).get("bin", ""))

            if external_call_always_success:
                # Mock successful call with empty return
                success = True
                return_data = b"\x00" * retSize
            elif not calling_code:
                # https://www.evm.codes/?fork=prague#f1 Call an account with no code will return success as true.
                success = True
                return_data = b''
            else:
                calling_tx = {
                    "from": this_address,
                    "to": address,
                    "value": value,
                    "data": calldata.hex()
                }
                called_return, _ = evm(calling_code, state, block, calling_tx, external_call_always_success)
                success = called_return.get("success", False)
                ret_hex = called_return.get("return", "")
                codecopy_logs.extend(called_return.get("codecopy_logs", []))
                events.extend(called_return.get("events", []))

                return_data = bytes.fromhex(ret_hex) if ret_hex else b""

            # CALLDATACOPY / CODECOPY / EXTCODECOPY for out of bound bytes, 0s will be copied
            # RETURNDATACOPY will raise a revert (EIP-211)
            # Critical: CALL's internal return data copy length is determined by **min(requestSize, returnedSize)**. No out-of-bounds check/revert occurs here.
            ## https://github.com/ethereum/go-ethereum/blob/master/core/vm/instructions.go
            copySize = min(retSize, len(return_data))
            for i in range(copySize):
                memory[retOffset + i] = return_data[i]
            if retOffset + copySize > highest_accessed_memory:
                highest_accessed_memory = math.ceil((retOffset + copySize) / 32) * 32
            stack.appendleft(int(success))

        elif next_inst == 0xF2:  # CALLCODE gas addr value argsOffset argsSize retOffset retSize
            gas, addr_int, value, argsOffset, argsSize, retOffset, retSize = [stack.popleft() for _ in range(7)]

            # TODO 实现
            raise Exception("绝大部分情况不会用到 但后续需要实现")

        elif next_inst == 0xF3:  # RETURN offset size
            offset, size = stack.popleft(), stack.popleft()
            value = bytes([memory.get(i, 0) for i in range(offset, offset + size)])
            # storage = copy.deepcopy(state.get(contract_addr, {}).get("storage", {})) # revert?
            return_obj['success'] = True
            return_obj['return'] = value.hex()  # noqa
            return return_obj, list(stack)

        elif next_inst == 0xF4:  # DELEGATECALL gas addr argsOffset argsSize retOffset retSize
            gas, addr_int, argsOffset, argsSize, retOffset, retSize = [stack.popleft() for _ in range(6)]
            if external_call_always_success:
                success = True
                return_data = b"\x00" * retSize
            else:
                # TODO 实现
                raise Exception("绝大部分情况不会用到 但后续需要实现")

            copySize = min(retSize, len(return_data))
            for i in range(copySize):
                memory[retOffset + i] = return_data[i]
            if retOffset + copySize > highest_accessed_memory:
                highest_accessed_memory = math.ceil((retOffset + copySize) / 32) * 32
            stack.appendleft(int(success))

        elif next_inst == 0xFA:  # STATICCALL gas addr argsOffset argsSize retOffset retSize
            gas, addr_int, argsOffset, argsSize, retOffset, retSize = [stack.popleft() for _ in range(6)]

            address = "0x" + addr_int.to_bytes(20, "big").hex()
            this_addr_int = int(tx.get("to", "0x0"), 16)
            this_address = "0x" + this_addr_int.to_bytes(20, "big").hex()

            calldata = bytes([memory.get(pos, 0) for pos in range(argsOffset, argsOffset + argsSize)])  # 4bytes-selector + call-args

            calling_code = bytes.fromhex(state.get(address, {}).get("code", {}).get("bin", ""))

            # This instruction is equivalent to CALL, except that it does not allow any state modifying instructions or sending ETH
            if external_call_always_success:
                success = True
                return_data = b"\x00" * retSize
            elif not calling_code:
                success = True
                return_data = b''
            else:
                calling_tx = {
                    "from": this_address,
                    "to": address,
                    "data": calldata.hex()
                }
                called_return, _ = evm(calling_code, state, block, calling_tx, external_call_always_success)
                success = called_return.get("success", False)
                ret_hex = called_return.get("return", "")
                codecopy_logs.extend(called_return.get("codecopy_logs", []))
                events.extend(called_return.get("events", []))

                return_data = bytes.fromhex(ret_hex) if ret_hex else b""

            copySize = min(retSize, len(return_data))
            for i in range(copySize):
                memory[retOffset + i] = return_data[i]
            if retOffset + copySize > highest_accessed_memory:
                highest_accessed_memory = math.ceil((retOffset + copySize) / 32) * 32
            stack.appendleft(int(success))

        elif next_inst == 0xFD:  # REVERT offset size
            offset, size = stack.popleft(), stack.popleft()
            value = bytes([memory.get(i, 0) for i in range(offset, offset + size)])
            # storage = copy.deepcopy(state.get(contract_addr, {}).get("storage", {})) # revert?
            return_obj['success'] = False
            return_obj['return'] = value.hex()  # noqa
            return return_obj, list(stack)

        elif next_inst == 0xFE:  # INVALID
            return_obj['success'] = False
            return_obj['return'] = ""  # noqa
            return return_obj, list(stack)

        elif next_inst == 0xFF:  # SELFDESTRUCT addr
            addr_int = stack.popleft()
            print('Warning', 'SELFDESTRUCT', 'do nothing')
            # Simplified: just consume the address, do nothing.

        else:
            raise Exception(f"Unsupported opcode: 0x{next_inst:02x} at position {cursor - 1}")

    return return_obj, list(stack)


def overflower(i: int, bits: int = 256) -> int:
    """Handle integer overflow for unsigned integers."""
    return i % (2 ** bits)


def twos_comp(val: int, bits: int = 256) -> int:
    """Convert unsigned integer to signed using two's complement."""
    if (val & (1 << (bits - 1))) != 0:
        val = val - (1 << bits)
    return val


def _test():
    with open('./evm.json') as f:
        data = json.load(f)

    total = len(data)
    for i, test in enumerate(data):
        print("Test #" + str(i + 1), "of", total, test['name'])

        code = bytes.fromhex(test['code']['bin'])
        asm = test['code']['asm']
        tx = test.get("tx", {})
        state = test.get("state", {})
        block = test.get("block", {})
        [returned, stack] = evm(code, state, block, tx)

        expected_stack = [int(x, 16) if x.startswith("0x") else int(x) for x in test['expect'].get('stack', [])]
        if stack != expected_stack:
            print("Stack doesn't match")
            print(" expected:", expected_stack)
            print("   actual:", stack)
            print("")
            print("Test code:")
            print(asm)
            print("")
            print("Progress: " + str(i) + "/" + str(len(data)))
            print("")
            break

        expected_return = test["expect"].get("return", "0x")
        return_value = returned.get("return", "0x")
        if return_value != expected_return:
            print("Return value doesn't match")
            print(" expected:", expected_return)
            print("   actual:", return_value)
            print("")
            print("Test code:")
            print(asm)
            print("")
            print("Progress: " + str(i) + "/" + str(len(data)))
            print("")
            break

        expect_constructor_codecopy_args = tuple(int(x, 16) if x.startswith("0x") else int(x) for x in test['expect'].get('constructor_codecopy_args', []))
        actual_constructor_codecopy_logs = [(dest, offset, size) for dest, offset, size, _, _ in returned.get("codecopy_logs", []) if dest == 0]
        if actual_constructor_codecopy_logs:
            for actual_args in actual_constructor_codecopy_logs:
                print("--- --- ---", actual_args)
            # return 前最后一个 dest=0 的 CODECOPY 就是我们要找的
        if expect_constructor_codecopy_args and expect_constructor_codecopy_args != next(reversed(actual_constructor_codecopy_logs), None):
            print("First CODECOPY args doesn't match")
            print(" expected:", expect_constructor_codecopy_args)
            print("   actual:", next(iter(actual_constructor_codecopy_logs), None))
            print("")
            print("Test code:")
            print(asm)
            print("")
            print("Progress: " + str(i) + "/" + str(len(data)))
            print("")
            break


if __name__ == '__main__':
    _test()
