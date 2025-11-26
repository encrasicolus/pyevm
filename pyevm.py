import json
import math
import copy

from eth_hash.auto import keccak


def evm(
        code: bytes,
        state: dict,
        block: dict,
        tx: dict,
        external_call_always_success: bool = False,
) -> tuple[dict[str, ...], list[int]]:
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
            - codecopy_logs: list of (dest_offset, code_offset, size) tuples
            - events: list of event logs
    """
    bytestring = code.hex()
    stack: list[int] = []
    memory: dict[int, int] = {}
    storage: dict[int, int] = {}
    new_storage = copy.deepcopy(storage)

    highest_accessed_memory = 0
    codecopy_logs: list[tuple[int, int, int]] = []
    events: list[dict] = []
    return_data: bytes = b""  # For RETURNDATASIZE/RETURNDATACOPY

    return_obj = {'highest_accessed_memory': highest_accessed_memory,
                  'codecopy_logs': codecopy_logs,
                  'events': events}
    # return_obj['success'] = ...
    # return_obj['return'] = ...

    while len(bytestring) > 0:
        next_inst = int(bytestring[:2], 16)
        bytestring = bytestring[2:]

        if next_inst == 0x00:  # STOP
            storage = copy.deepcopy(new_storage)
            return return_obj, stack

        elif next_inst == 0x01:  # ADD a b
            result = overflower(stack[0] + stack[1])
            stack = [result] + stack[2:]

        elif next_inst == 0x02:  # MUL a b
            result = overflower(stack[0] * stack[1])
            stack = [result] + stack[2:]

        elif next_inst == 0x03:  # SUB a b
            result = overflower(stack[0] - stack[1])
            stack = [result] + stack[2:]

        elif next_inst == 0x04:  # DIV a b
            if stack[1] == 0:
                result = 0
            else:
                result = overflower(stack[0] // stack[1])
            stack = [result] + stack[2:]

        elif next_inst == 0x05:  # SDIV a b
            if stack[1] == 0:
                result = 0
            else:
                result = overflower(twos_comp(stack[0]) // twos_comp(stack[1]))
            stack = [result] + stack[2:]

        elif next_inst == 0x06:  # MOD a b
            if stack[1] == 0:
                result = 0
            else:
                result = stack[0] % stack[1]
            stack = [result] + stack[2:]

        elif next_inst == 0x07:  # SMOD a b
            if stack[1] == 0:
                result = 0
            else:
                result = overflower(twos_comp(stack[0]) % twos_comp(stack[1]))
            stack = [result] + stack[2:]

        elif next_inst == 0x08:  # ADDMOD a b N
            a, b, N = stack[0], stack[1], stack[2]
            if N == 0:
                result = 0
            else:
                result = (a + b) % N
            stack = [result] + stack[3:]

        elif next_inst == 0x09:  # MULMOD a b N
            a, b, N = stack[0], stack[1], stack[2]
            if N == 0:
                result = 0
            else:
                result = (a * b) % N
            stack = [result] + stack[3:]

        elif next_inst == 0x0A:  # EXP a exponent
            base, exponent = stack[0], stack[1]
            result = overflower(pow(base, exponent, 2 ** 256))
            stack = [result] + stack[2:]

        elif next_inst == 0x0B:  # SIGNEXTEND b x
            b, x = stack[0], stack[1]
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
            stack = [result] + stack[2:]

        elif next_inst == 0x10:  # LT a b
            if stack[0] < stack[1]:
                result = 1
            else:
                result = 0
            stack = [result] + stack[2:]

        elif next_inst == 0x11:  # GT a b
            if stack[0] > stack[1]:
                result = 1
            else:
                result = 0
            stack = [result] + stack[2:]

        elif next_inst == 0x12:  # SLT a b
            if twos_comp(stack[0]) < twos_comp(stack[1]):
                result = 1
            else:
                result = 0
            stack = [result] + stack[2:]

        elif next_inst == 0x13:  # SGT a b
            if twos_comp(stack[0]) > twos_comp(stack[1]):
                result = 1
            else:
                result = 0
            stack = [result] + stack[2:]

        elif next_inst == 0x14:  # EQ a b
            if stack[0] == stack[1]:
                result = 1
            else:
                result = 0
            stack = [result] + stack[2:]

        elif next_inst == 0x15:  # ISZERO a
            if stack[0] == 0:
                result = 1
            else:
                result = 0
            stack = [result] + stack[1:]

        elif next_inst == 0x16:  # AND a b
            result = stack[0] & stack[1]
            stack = [result] + stack[2:]

        elif next_inst == 0x17:  # OR a b
            result = stack[0] | stack[1]
            stack = [result] + stack[2:]

        elif next_inst == 0x18:  # XOR a b
            result = stack[0] ^ stack[1]
            stack = [result] + stack[2:]

        elif next_inst == 0x19:  # NOT a
            result = overflower(~stack[0])
            stack = [result] + stack[1:]

        elif next_inst == 0x1A:  # BYTE i x
            if stack[0] > 32:
                result = 0
            else:
                result = (stack[1] >> (248 - (8 * stack[0]))) & 0xFF
            stack = [result] + stack[2:]

        elif next_inst == 0x1B:  # SHL shift value
            shift, value = stack[0], stack[1]
            if shift >= 256:
                result = 0
            else:
                result = overflower(value << shift)
            stack = [result] + stack[2:]

        elif next_inst == 0x1C:  # SHR shift value
            shift, value = stack[0], stack[1]
            if shift >= 256:
                result = 0
            else:
                result = value >> shift
            stack = [result] + stack[2:]

        elif next_inst == 0x1D:  # SAR shift value
            shift, value = stack[0], stack[1]
            signed_value = twos_comp(value)
            if shift >= 256:
                result = 0 if signed_value >= 0 else overflower(-1)
            else:
                result = overflower(signed_value >> shift)
            stack = [result] + stack[2:]

        elif next_inst == 0x20:  # SHA3 offset size (actually KECCAK256)
            value = [memory.get(i, 0) for i in range(stack[0], stack[0] + stack[1])]
            if stack[0] + stack[1] > highest_accessed_memory:
                highest_accessed_memory = math.ceil((stack[0] + stack[1]) / 32) * 32
            data = bytes(value)
            result = int.from_bytes(keccak(data), "big")
            stack = [result] + stack[2:]

        elif next_inst == 0x30:  # ADDRESS
            stack = [int(tx.get("to", '0x0'), 16)] + stack

        elif next_inst == 0x31:  # BALANCE addr
            stack = [int(state.get(hex(stack[0]), {}).get("balance", 0))] + stack[1:]

        elif next_inst == 0x32:  # ORIGIN
            stack = [int(tx.get("origin", ""), 16)] + stack

        elif next_inst == 0x33:  # CALLER
            stack = [int(tx.get("from", ""), 16)] + stack

        elif next_inst == 0x34:  # CALLVALUE
            stack = [int(tx.get("value", 0))] + stack

        elif next_inst == 0x35:  # CALLDATALOAD i
            data = tx.get("data", "")
            offset = stack[0]
            data_slice = data[offset * 2:].ljust(64, "0")
            stack = [int(data_slice[:64], 16)] + stack[1:]

        elif next_inst == 0x36:  # CALLDATASIZE
            stack = [len(str(tx.get("data", ""))) // 2] + stack

        elif next_inst == 0x37:  # CALLDATACOPY destOffset offset size
            dest_offset, data_offset, size = stack[0], stack[1], stack[2]
            data = tx.get("data", "")
            value = bytes.fromhex(data[data_offset * 2:(data_offset + size) * 2].ljust(size * 2, "0"))
            for i in range(size):
                if i < len(value):
                    memory[dest_offset + i] = value[i]
                else:
                    memory[dest_offset + i] = 0
            if dest_offset + size > highest_accessed_memory:
                highest_accessed_memory = math.ceil(dest_offset + size)
            stack = stack[3:]

        elif next_inst == 0x38:  # CODESIZE
            stack = [len(code.hex()) // 2] + stack

        elif next_inst == 0x39:  # CODECOPY destOffset offset size
            dest_offset, code_offset, size = stack[0], stack[1], stack[2]
            codecopy_logs.append((dest_offset, code_offset, size))
            code_hex = code.hex()
            value = bytes.fromhex(code_hex[code_offset * 2:(code_offset + size) * 2].ljust(size * 2, "0"))
            for i in range(size):
                if i < len(value):
                    memory[dest_offset + i] = value[i]
                else:
                    memory[dest_offset + i] = 0
            if dest_offset + size > highest_accessed_memory:
                highest_accessed_memory = math.ceil(dest_offset + size)
            stack = stack[3:]

        elif next_inst == 0x3A:  # GASPRICE
            stack = [int(tx.get("gasprice", 0))] + stack

        elif next_inst == 0x3B:  # EXTCODESIZE addr
            stack = [len(state.get(hex(stack[0]), {}).get("code", {}).get("bin", "")) // 2] + stack[1:]

        elif next_inst == 0x3C:  # EXTCODECOPY addr destOffset codeOffset size
            addr, mem_offset, data_offset, size = stack[:4]
            extcode = state.get(hex(addr), {}).get("code", {}).get("bin", "")
            value = bytes.fromhex(extcode[data_offset * 2:(data_offset + size) * 2].ljust(size * 2, "0"))
            for i in range(size):
                if i < len(value):
                    memory[mem_offset + i] = value[i]
                else:
                    memory[mem_offset + i] = 0
            if mem_offset + size > highest_accessed_memory:
                highest_accessed_memory = mem_offset + size
            stack = stack[4:]

        elif next_inst == 0x3D:  # RETURNDATASIZE
            stack = [len(return_data)] + stack

        elif next_inst == 0x3E:  # RETURNDATACOPY destOffset offset size
            dest_offset, data_offset, size = stack[0], stack[1], stack[2]
            for i in range(size):
                if data_offset + i < len(return_data):
                    memory[dest_offset + i] = return_data[data_offset + i]
                else:
                    memory[dest_offset + i] = 0
            if dest_offset + size > highest_accessed_memory:
                highest_accessed_memory = math.ceil(dest_offset + size)
            stack = stack[3:]

        elif next_inst == 0x3F:  # EXTCODEHASH addr
            addr = stack[0]
            ext_code = state.get(hex(addr), {}).get("code", {}).get("bin", "")
            if ext_code:
                result = int.from_bytes(keccak(bytes.fromhex(ext_code)), "big")
            else:
                result = 0
            stack = [result] + stack[1:]

        elif next_inst == 0x41:  # COINBASE
            stack = [int(block.get("coinbase", '0x0'), 16)] + stack

        elif next_inst == 0x42:  # TIMESTAMP
            stack = [int(block.get("timestamp", 0))] + stack

        elif next_inst == 0x43:  # NUMBER
            stack = [int(block.get("number", 0))] + stack

        elif next_inst == 0x44:  # DIFFICULTY (PREVRANDAO after merge)
            stack = [int(block.get("difficulty", '0x0'), 16)] + stack

        elif next_inst == 0x45:  # GASLIMIT
            stack = [int(block.get("gaslimit", '0x0'), 16)] + stack

        elif next_inst == 0x46:  # CHAINID
            stack = [int(block.get("chainid", 0))] + stack

        elif next_inst == 0x47:  # SELFBALANCE
            stack = [int(state.get(hex(int(tx.get("to", '0x0'), 16)), {}).get("balance", 0))] + stack

        elif next_inst == 0x48:  # BASEFEE (London 2021)
            stack = [int(block.get("basefee", 0))] + stack

        elif next_inst == 0x50:  # POP
            stack = stack[1:]

        elif next_inst == 0x51:  # MLOAD offset
            value = [memory.get(i, 0) for i in range(stack[0], stack[0] + 32)]
            if stack[0] + 32 > highest_accessed_memory:
                highest_accessed_memory = math.ceil((stack[0] + 32) / 32) * 32
            hex_value = "".join([hex(i)[2:].zfill(2) for i in value]) + "00" * (32 - len(value))
            stack = [int(hex_value, 16)] + stack[1:]

        elif next_inst == 0x52:  # MSTORE offset value
            value = bytes.fromhex(hex(stack[1])[2:].zfill(64))
            for i in range(32):
                memory[stack[0] + i] = value[i]
            if stack[0] + 32 > highest_accessed_memory:
                highest_accessed_memory = math.ceil((stack[0] + 32) / 32) * 32
            stack = stack[2:]

        elif next_inst == 0x53:  # MSTORE8 offset value
            memory[stack[0]] = stack[1] & 0xFF
            if stack[0] > highest_accessed_memory:
                highest_accessed_memory = math.ceil((stack[0]) / 32) * 32
            stack = stack[2:]

        elif next_inst == 0x54:  # SLOAD key
            stack = [new_storage.get(stack[0], 0)] + stack[1:]

        elif next_inst == 0x55:  # SSTORE key value
            key, value = stack[:2]
            new_storage[key] = value
            stack = stack[2:]

        elif next_inst == 0x56:  # JUMP dest
            bytestring = code.hex()[stack[0] * 2:]
            stack = stack[1:]
            assert bytestring[:2] == "5b", f"Invalid JUMP destination: {stack[0]}"

        elif next_inst == 0x57:  # JUMPI dest condition
            if stack[1] > 0:
                bytestring = code.hex()[stack[0] * 2:]
                assert bytestring[:2] == "5b", f"Invalid JUMPI destination: {stack[0]}"
            stack = stack[2:]

        elif next_inst == 0x58:  # PC
            counter = (len(code.hex()) - (len(bytestring) + 2)) // 2
            stack = [counter] + stack

        elif next_inst == 0x59:  # MSIZE
            stack = [highest_accessed_memory] + stack

        elif next_inst == 0x5A:  # GAS
            stack = [0xFFFFFFFF] + stack  # Return large value as we don't track gas

        elif next_inst == 0x5B:  # JUMPDEST
            pass  # No operation, just a valid jump destination marker

        elif next_inst == 0x5F:  # PUSH0 (Shanghai 2023)
            stack = [0] + stack

        elif 0x60 <= next_inst <= 0x7F:  # PUSH1-PUSH32
            bytes_to_append = next_inst - 0x60 + 1
            stack = [int(bytestring[0:bytes_to_append * 2], 16)] + stack
            bytestring = bytestring[bytes_to_append * 2:]

        elif 0x80 <= next_inst <= 0x8F:  # DUP1-DUP16
            position_to_duplicate = next_inst - 0x80
            stack = [stack[position_to_duplicate]] + stack

        elif 0x90 <= next_inst <= 0x9F:  # SWAP1-SWAP16
            position_to_swap = next_inst - 0x90 + 1
            stack[0], stack[position_to_swap] = stack[position_to_swap], stack[0]

        elif 0xA0 <= next_inst <= 0xA4:  # LOG0-LOG4
            num_topics = next_inst - 0xA0
            offset, size = stack[0], stack[1]
            topics = stack[2:2 + num_topics]
            log_data = bytes([memory.get(offset + i, 0) for i in range(size)])
            events.append({
                "topics": [hex(t) for t in topics],
                "data": log_data.hex(),
            })
            stack = stack[2 + num_topics:]

        elif next_inst == 0xF0:  # CREATE value offset size
            create_value, offset, size = stack[0], stack[1], stack[2]
            # Get init code from memory
            init_code = bytes([memory.get(offset + i, 0) for i in range(size)])

            # Compute contract address: keccak256(rlp([sender, nonce]))[12:]
            # Simplified: use a deterministic address based on sender
            sender_addr = int(tx.get("to", "0x0"), 16)
            # Simple nonce tracking via a counter based on code position
            nonce = 0
            addr_preimage = sender_addr.to_bytes(20, "big") + nonce.to_bytes(8, "big")
            new_addr = int.from_bytes(keccak(addr_preimage)[12:], "big")

            # Execute init code to get runtime code
            if init_code:
                new_tx = {
                    "from": tx.get("to", ""),
                    "to": hex(new_addr),
                    "value": create_value,
                }
                [return_value, _] = evm(init_code, state, block, new_tx, external_call_always_success)
                runtime_code = return_value.get("return", "")
                success = return_value.get("success", False)

                if success:
                    # Store the new contract in state
                    state[hex(new_addr)] = {
                        "balance": str(create_value),
                        "code": {"bin": runtime_code},
                    }
                    result = new_addr
                else:
                    result = 0
            else:
                # Empty init code, just create an account with the value
                state[hex(new_addr)] = {
                    "balance": str(create_value),
                    "code": {"bin": ""},
                }
                result = new_addr

            stack = [result] + stack[3:]

        elif next_inst == 0xF1:  # CALL gas addr value argsOffset argsSize retOffset retSize
            gas, addr, value, argsOffset, argsSize, retOffset, retSize = stack[:7]

            if external_call_always_success:
                # Mock successful call with empty return
                stack = [1] + stack[7:]
                return_data = b"\x00" * retSize
                for i in range(retSize):
                    memory[retOffset + i] = 0
            else:
                called_code = bytes.fromhex(state.get(hex(addr), {}).get("code", {}).get("bin", ""))
                old_from = tx.get("from", "")
                tx["from"] = tx.get("to", "")
                tx["to"] = hex(addr)
                [return_value, _] = evm(called_code, state, block, tx, external_call_always_success)
                tx["from"] = old_from
                success = return_value.get("success", False)
                ret_hex = return_value.get("return", "")
                return_data = bytes.fromhex(ret_hex) if ret_hex else b""
                result = bytes.fromhex(ret_hex.zfill(retSize * 2)) if ret_hex else b"\x00" * retSize

                if success:
                    stack = [1] + stack[7:]
                else:
                    stack = [0] + stack[7:]

                for i in range(min(retSize, len(result))):
                    memory[retOffset + i] = result[i]

            if retOffset + retSize > highest_accessed_memory:
                highest_accessed_memory = retOffset + retSize

        elif next_inst == 0xF2:  # CALLCODE gas addr value argsOffset argsSize retOffset retSize
            gas, addr, value, argsOffset, argsSize, retOffset, retSize = stack[:7]
            if external_call_always_success:
                stack = [1] + stack[7:]
                return_data = b"\x00" * retSize
                for i in range(retSize):
                    memory[retOffset + i] = 0
            else:
                # Simplified: treat like CALL for now
                stack = [0] + stack[7:]
                return_data = b""
            if retOffset + retSize > highest_accessed_memory:
                highest_accessed_memory = retOffset + retSize

        elif next_inst == 0xF3:  # RETURN offset size
            offset, size = stack[:2]
            value = [memory.get(i, 0) for i in range(offset, offset + size)]
            result = "".join([hex(val)[2:].zfill(2) for val in value])
            storage = copy.deepcopy(new_storage)
            return_obj['success'] = True
            return_obj['return'] = result  # noqa
            return return_obj, stack[2:]

        elif next_inst == 0xF4:  # DELEGATECALL gas addr argsOffset argsSize retOffset retSize
            gas, addr, argsOffset, argsSize, retOffset, retSize = stack[:6]
            if external_call_always_success:
                stack = [1] + stack[6:]
                return_data = b"\x00" * retSize
                for i in range(retSize):
                    memory[retOffset + i] = 0
            else:
                # Simplified: return failure
                stack = [0] + stack[6:]
                return_data = b""
            if retOffset + retSize > highest_accessed_memory:
                highest_accessed_memory = retOffset + retSize

        elif next_inst == 0xF5:  # CREATE2 value offset size salt
            value, offset, size, salt = stack[0], stack[1], stack[2], stack[3]
            # Simplified CREATE2: just return a placeholder address
            result = 0x1234567890ABCDEF  # Placeholder address
            stack = [result] + stack[4:]

        elif next_inst == 0xFA:  # STATICCALL gas addr argsOffset argsSize retOffset retSize
            gas, addr, argsOffset, argsSize, retOffset, retSize = stack[:6]
            if external_call_always_success:
                stack = [1] + stack[6:]
                return_data = b"\x00" * retSize
                for i in range(retSize):
                    memory[retOffset + i] = 0
            else:
                called_code = bytes.fromhex(state.get(hex(addr), {}).get("code", {}).get("bin", ""))
                old_from = tx.get("from", "")
                tx["from"] = tx.get("to", "")
                tx["to"] = hex(addr)
                [return_value, _] = evm(called_code, state, block, tx, external_call_always_success)
                tx["from"] = old_from
                success = return_value.get("success", False)
                ret_hex = return_value.get("return", "")
                return_data = bytes.fromhex(ret_hex) if ret_hex else b""
                result = bytes.fromhex(ret_hex.zfill(retSize * 2)) if ret_hex else b"\x00" * retSize

                if success:
                    stack = [1] + stack[6:]
                else:
                    stack = [0] + stack[6:]

                for i in range(min(retSize, len(result))):
                    memory[retOffset + i] = result[i]

            if retOffset + retSize > highest_accessed_memory:
                highest_accessed_memory = retOffset + retSize

        elif next_inst == 0xFD:  # REVERT offset size
            offset, size = stack[:2]
            value = [memory.get(i, 0) for i in range(offset, offset + size)]
            result = "".join([hex(val)[2:].zfill(2) for val in value])
            return_obj['success'] = False
            return_obj['return'] = result  # noqa
            return return_obj, stack[2:]

        elif next_inst == 0xFE:  # INVALID
            return_obj['success'] = False
            return_obj['return'] = ""  # noqa
            return return_obj, stack

        elif next_inst == 0xFF:  # SELFDESTRUCT addr
            # Simplified: just consume the address
            stack = stack[1:]

        else:
            raise Exception(f"Unsupported opcode: 0x{next_inst:02x} at position {(len(code.hex()) - len(bytestring) - 2) // 2}")

    return return_obj, stack


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
            print(test['code']['asm'])
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
            print(test['code']['asm'])
            print("")
            print("Progress: " + str(i) + "/" + str(len(data)))
            print("")
            break


if __name__ == '__main__':
    _test()
