# Inspired by https://github.com/0xAlexei/INFILTRATE2019/blob/master/PCodeMallocDemo/MallocTrace.java

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp, Varnode
from ghidra.program.model.symbol import SourceType

# Setup decompiler
options = DecompileOptions()
monitor = ConsoleTaskMonitor()
decomplib = DecompInterface()
decomplib.setOptions(options)
decomplib.openProgram(currentProgram)
mem = currentProgram.getMemory()

explored_function_names = []

def get_u16(addr_obj):
    return mem.getShort(addr_obj) & 0xFFFF

def get_u32(addr_obj):
    return mem.getInt(addr_obj) & 0xFFFFFFFF

def addr(offset):
    return currentProgram.getImageBase().getAddressSpace().getAddress(offset)

def get_last_r0_mov(instruction):
    count = 0
    iter_instruction = instruction
    found_instruction = None
    while count < 10:
        # feed loop
        iter_instruction = iter_instruction.getPrevious()
        count += 1
        # check if we have a mov instr
        mnem = iter_instruction.getMnemonicString()
        if not iter_instruction and mnem != "A2_tfrsi" and mnem != "SA1_seti":
            continue
        # check if first operand is r0
        # print(iter_instruction.getDefaultOperandRepresentation(0))
        if iter_instruction.getDefaultOperandRepresentation(0) != "R0":
            continue
        # if checks pass, this is the mov
        found_instruction = iter_instruction
        break
    return found_instruction

def find_diag_handlers(target_func_addr, thunk=False):
    # Find diag command handlers passed to target_function_name and rename their handler funcs

    # Check explored function list
    if target_func_addr in explored_function_names:
        return
    else:
        explored_function_names.append(target_func_addr)

    # Get list of unique functions that call this function
    refs = currentProgram.referenceManager.getReferencesTo(target_func_addr)
    for func_call in refs:
        call_addr = func_call.getFromAddress()
        print(hex(call_addr.getOffset()).replace("L", ""))
        instruction = getInstructionAt(call_addr)
        # check that it's a jump that goes to the target function
        found = False
        mnem = instruction.getMnemonicString()
        if mnem == "J2_jump" or mnem == "J2_call":
            jump_dest = instruction.getOperandReferences(0)[0].getToAddress()
            if jump_dest == target_func_addr:
                # check the R0 move instruction right in front of the jump
                arg_instr = get_last_r0_mov(instruction)
                if arg_instr:
                    arg_offset = int(arg_instr.getDefaultOperandRepresentation(1), 16)
                    # TODO: Improve this addr sanity check
                    if arg_offset > 0x5400000:
                        found = True
                        # Get diagpkt_user_table_entry_type ptr
                        ute_addr = addr(arg_offset + 0x10)
                        ute_addr = addr(get_u32(ute_addr)) # deref ptr
                        # Grab cmd code and handler func ptr from table entry
                        cmd_code_lo = get_u16(ute_addr)
                        cmd_code_hi = get_u16(ute_addr.add(0x2))
                        func_offset = get_u32(ute_addr.add(0x4))
                        if func_offset == 0:
                            print("Skipping null cmd def!")
                            continue
                        # Build handler func name
                        handler_func_name = hex(cmd_code_lo).replace("0x", "").replace("L", "")
                        handler_func_name += "_"
                        handler_func_name += hex(cmd_code_hi).replace("0x", "").replace("L", "")
                        handler_func_name += "_diag_cmd_handler"
                        print(handler_func_name)
                        # Rename handler func
                        func_addr = addr(func_offset)
                        print("Renaming function: " + str(func_addr))
                        func = getFunctionContaining(func_addr)
                        if not func:
                            func = createFunction(func_addr, "")
                        if not func:
                            print("Failed to rename func!")
                            continue
                        func.setName(handler_func_name, SourceType.ANALYSIS)
        # if we still haven't found a table reg ptr, this is probably a thunk and it's using vars for the ptr
        possible_thunk_func = getFunctionContaining(call_addr)
        if not possible_thunk_func or not possible_thunk_func.isThunk():
            continue        
        if not found and not thunk:
            print("Possible thunk found: " + hex(call_addr.getOffset()).replace("L", ""))
            find_diag_handlers(getFirstInstruction(possible_thunk_func).getAddress(), thunk=True)

# Find diag handlers and change their func names
# This function can be kinda hard to find without reversing a lot of diag code
find_diag_handlers(toAddr("diagpkt_tbl_reg")) # 0xc05dfea4