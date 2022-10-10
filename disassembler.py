#!/usr/bin/env python2
# -*- coding:utf-8 -*-

from __future__ import print_function

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
# actually you don't need to import by yourself, but it makes much "explicit"
import __main__ as ghidra_app

# Distance from address to byte
# |<---------->|
# 00401000      89 c8      MOV EAX, this
DISTANCE_FROM_ADDRESS_TO_BYTE = 15

# Distance from byte to instruction
#               |<------->|
# 00401000      89 c8      MOV EAX, this
DISTANCE_FROM_BYTE_TO_INST = 15

# Output format of instructions
MSG_FORMAT = ' {{addr:<{0}}} {{byte:<{1}}} {{inst}}\n'.format(
    DISTANCE_FROM_ADDRESS_TO_BYTE,
    DISTANCE_FROM_ADDRESS_TO_BYTE+DISTANCE_FROM_BYTE_TO_INST 
)


def unoverflow(x):
    return (abs(x) ^ 0xff) + 1


def to_hex(integer):
    return '{:02x}'.format(integer)


def _get_function_signature(func):
    # Get function signature
    calling_conv = func.getDefaultCallingConventionName()
    params = func.getParameters()

    return '\n{calling_conv} {func_name}({params})\n'.format(
        calling_conv=calling_conv,
        func_name=func.getName(),
        params=', '.join([str(param).replace('[', '').replace(']', '').split('@')[0] for param in params]))


def _get_instructions(func):
    instructions = ''

    # Get instructions in function
    func_addr = func.getEntryPoint()
    insts = ghidra_app.currentProgram.getListing().getInstructions(func_addr, True)

    # Process each instruction
    for inst in insts:
        if ghidra_app.getFunctionContaining(inst.getAddress()) != func:
            break

        instructions += MSG_FORMAT.format(
            addr=inst.getAddressString(True, True),
            byte=' '.join([to_hex(b) if b >= 0 else to_hex(unoverflow(b)) for b in inst.getBytes()]),
            inst=inst
        )

    return instructions


def disassemble_func(func):
    '''disassemble given function, and returns as string.
    Args:
        func (ghidra.program.model.listing.Function): function to be disassembled
    Returns:
        string: disassembled function with function signature and instructions
    '''

    return  _get_function_signature(func) + _get_instructions(func)


def disassemble(program):
    '''disassemble given program.
    Args:
        program (ghidra.program.model.listing.Program): program to be disassembled
    Returns:
        string: all disassembled functions 
    '''

    disasm_result = ''

    # Enum functions and disassemble
    funcs = program.getListing().getFunctions(True)
    for func in funcs:
        disasm_result += disassemble_func(func)

    return disasm_result


def run():
    args = ghidra_app.getScriptArgs()
    if len(args) > 1:
        print('[!] need output path, see following\n\
Usage: ./analyzeHeadless <PATH_TO_GHIDRA_PROJECT> <PROJECT_NAME> \
-process|-import <TARGET_FILE> [-scriptPath <PATH_TO_SCRIPT_DIR>] \
-postScript|-preScript disassemble.py <PATH_TO_OUTPUT_FILE>')
        return

    # If no output path given, 
    # <CURRENT_PROGRAM>.asm will be saved in current dir
    if len(args) == 0:
        cur_program_name = ghidra_app.currentProgram.getName()
        output = '{}.asm'.format(''.join(cur_program_name.split('.')[:-1]))
    else:
        output = args[0]

    # Get disassembled code
    disassembled = disassemble(ghidra_app.currentProgram)
    # Save to output file
    with open(output, 'w') as fw:
        fw.write(disassembled)
        print('[*] success. save to -> {}'.format(output))
    
# Starts execution here
if __name__ == '__main__':
    run()
    
