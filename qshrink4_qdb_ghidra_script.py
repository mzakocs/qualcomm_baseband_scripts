# Inspired by https://github.com/0xAlexei/INFILTRATE2019/blob/master/PCodeMallocDemo/MallocTrace.java

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp, Varnode

# Setup decompiler
options = DecompileOptions()
monitor = ConsoleTaskMonitor()
decomplib = DecompInterface()
decomplib.setOptions(options)
decomplib.openProgram(currentProgram)

class QDBEntry():

    def __init__(self):
        self.seqnum = 0
        self.line = 0
        self.level = 0
        self.client = 0
        self.logstring = ""

class QDB():

    def __init__(self, file_path):
        # Init member vars
        self.entries = {} # hash -> QDBEntry
        self.explored_function_names = []
        # Open QDB file
        self.f = open(file_path, "r")
        # Parse file
        self.parse()

    def parse(self):
        # Read lines
        lines = self.f.readlines()
        for line in lines:
            # We only want to parse the content xml section
            if "<\\Content>" in line:
                return
            # Check for comments and xml defs
            if line.startswith("#") or line.startswith("<") or len(line) < 5:
                continue
            # Parse db line
            split = line.split(":")
            entry = QDBEntry()
            entry.hash = int(split[0])
            entry.line = int(split[1])
            entry.level = int(split[2])
            entry.client = int(split[3])
            entry.value = ":".join(split[4:])
            self.entries[entry.hash] = entry

    def arg_to_hash(self, hash_int):
        # converts a qdb arg value to the queryable hash
        return (hash_int >> 3) & 0xFFFFF

    def get_pcode_calls(self, target_func, called_func_addr):
        # Finds all calls to called_func_addr in target_func
        # Make sure function is decompiled
        h_function = None
        d_res = decomplib.decompileFunction(target_func, decomplib.getOptions().getDefaultTimeout(), getMonitor())
        if not d_res:
            print("Error in decompiling " + str(target_func))
            return []
        h_function = d_res.getHighFunction()
        if not h_function:
            print("Error in decompiling " + str(target_func))
            return []
            
        # Get all pcode call sites
        pcode_call_sites = []
        for op in h_function.getPcodeOps():
            # Check if PCode node is a call
            if op.getOpcode() != PcodeOp.CALL:
                continue
            # Check call addr
            called_addr = op.getInput(0)
            if type(called_addr) == Varnode or called_addr == 0:
                continue
            if not called_addr.isAddress() or called_addr.getAddress() != called_func_addr:
                continue
            # Add to call list
            pcode_call_sites.append(op)
        return pcode_call_sites

    def comment_function_references(self, target_function_name, thunk=False):
        # Add QDB strings as comments to the function provided
        #   First arg of the function must be the message hash/number thing, ex. 0xf8016138 
        
        # Check explored function list
        if target_function_name in self.explored_function_names:
            return
        else:
            self.explored_function_names.append(target_function_name)

        # Get list of unique functions that call this function
        target_func_addr = toAddr(target_function_name)
        if not target_func_addr:
            print("Function not found: " + target_function_name)
            return
        refs = currentProgram.referenceManager.getReferencesTo(target_func_addr)
        calling_funcs = {}
        for func_call in refs:
            call_addr = func_call.getFromAddress()
            calling_func = getFunctionContaining(call_addr)
            # Check if callsite is valid and that we don't already have it
            # if call_addr.getOffset() != 0xd9e27cbc:
            #     continue
            if calling_func and calling_func.getName() not in calling_funcs:
                calling_funcs[calling_func.getName()] = calling_func
        
        # Go through the AST of all calling functions and get args
        for calling_func_name, calling_func in calling_funcs.items():
            print(calling_func_name)
            call_sites = self.get_pcode_calls(calling_func, target_func_addr)

            # Get every call site in this function and build function comment
            comment_header = "\nQDB LOG STRINGS FOUND:\n\n"
            new_comment = ""
            for call_site in call_sites:
                # Get arg and make sure it's a constant
                #   TODO: A couple functions use vars for this arg, add ability to trace them
                msg_arg = call_site.getInput(1)
                if not msg_arg or not msg_arg.isConstant():
                    continue
                # Convert arg to qdb hash
                arg = msg_arg.getOffset()
                if arg < 0x10000000: # arg hash usually a pretty large num, check it
                    continue
                hash = self.arg_to_hash(arg)
                # Get log string
                if hash not in self.entries:
                    print("Hash not found: " + hex(arg) + " -> " + hex(hash))
                    continue
                logstr = self.entries[hash].value
                # Build comment
                new_comment += hex(arg).replace("L", "")
                new_comment += " = "
                new_comment += logstr
                if thunk:
                    new_comment += "(from thunk "
                    new_comment += target_function_name
                    new_comment += ")"
                new_comment += "\n"
            # Put comment on function
            print(new_comment)
            # If it couldn't find any hashes, this is likely a thunk for msg_v4_send_*
            if new_comment == "":
                # Check that we're not already in a thunk so we don't recurse too deep
                if not thunk:
                    print("Possible thunk found: " + calling_func_name)
                    qdb.comment_function_references(calling_func_name, thunk=True)
                continue
            # Make sure we don't have this comment in the header already
            # Add comment header
            old_comment = calling_func.getComment()
            if old_comment and old_comment.startswith(comment_header):
                new_comment = old_comment + new_comment
            else:
                new_comment = comment_header + new_comment
            calling_func.setComment(new_comment)

    def clear_all_function_comments(self):
        for f in currentProgram.getFunctionManager().getFunctions(True):
            f.setComment(None)

# Parse QDB
print("Parsing QDB File...")
qdb = QDB("/home/mitchbuntu/Documents/Github/pixel_5/pixel_5_mar_2023/modem/saipan/_qdsp6m.qdb.extracted/40")
print("Done!")

# Clear all functions
# NOTE: Be careful with this! It will wipe all function header comments!
#       This does not clear variable and pre comments, just the block header comment for functions. If you're worried, test on a fresh DB first!
print("Clearing all function comments...")
qdb.clear_all_function_comments()
print("Done!")

# Process msg functions
qdb.comment_function_references("msg_v4_send")      # 0xc05a5240
qdb.comment_function_references("msg_v4_send_1")    # 0xc018768c
qdb.comment_function_references("msg_v4_send_2")    # 0xc059dd20
qdb.comment_function_references("msg_v4_send_3")    # 0xc059db60
qdb.comment_function_references("msg_v4_send_n")    # 0xc01874a8

# Comment out all Ghidra includes and decompiler instantiation to use this file standalone, example below
# print(qdb.entries[qdb.arg_to_hash(0xf80188d8)].value)