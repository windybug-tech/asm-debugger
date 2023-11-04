import sys
import argparse
import ctypes
import struct
from keystone import *

def parser():
    parser = argparse.ArgumentParser(
        prog="x64ShellcodeTool",
        description="A tool to create and debug x64 shellcode.")

    parser.add_argument('-d', '--debug', action="store_true")
    parser.add_argument('-p', '--print', action="store_true")

    arg = parser.parse_args()
    return arg

def printShellcode(enc):
    printShellcode = ""
    # quick loop to format shellcode for import into C code
    newlineCheck = 1

    for i in enc:
        if (newlineCheck % 12 == 0):
            printShellcode += "0x{0:02x},".format(int(i)).rstrip("\n")
            printShellcode += "\n\t"
            newlineCheck = 1

        else:
            printShellcode += "0x{0:02x}, ".format(int(i)).rstrip("\n")
            newlineCheck += 1

    print("unsigned char shellcode[] = {\n\t" + printShellcode + "\n};")

def debug(shellcode):
    # Fixing 32-bit allocation issue with c_int
    # since Windows interprets c_int as 32-bit. VA now returns 64 bit value
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p

    # API call setup using CTypes. Will inject into python process.
    # Memory allocated with MEM_COMMIT | MEM_RESERVE and PAGE_EXECUTE_READWRITE perms
    vaPtr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                                ctypes.c_int(len(shellcode)),
                                                ctypes.c_int(0x3000),
                                                ctypes.c_int(0x40))

    # Creating a C char array out of the data in shellcode
    buffer = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

    # Specifying required arg types for RtlMoveMemory
    ctypes.windll.kernel32.RtlMoveMemory.argtypes = ( ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t )

    # Copy shellcode to allocated memory vaPtr
    # still have to typecast vaPtr a VOID*
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.cast(vaPtr, ctypes.c_void_p),
                                         buffer,
                                         ctypes.c_size_t(len(shellcode)))

    print("Shellcode loaded at the following address: %s" % hex(vaPtr))
    input("Press <enter> to execute shellcode...")

    hThread = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                                  ctypes.c_int(0),
                                                  ctypes.cast(vaPtr, ctypes.c_void_p),
                                                  ctypes.c_int(0),
                                                  ctypes.c_int(0),
                                                  ctypes.c_int(0))

    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(hThread), ctypes.c_int(-1))

def main():

    # Call parser to parse cmd line args
    arg = parser()

    # x64-based shellcode - Launches MessageBoxA prompt
    # Offsets:
    # PEB -> 0x60, _PEB_LDR_DATA -> 0x18
    # InLoadOrderModuleList -> 0x10, InMemoryOrderModuleList -> 0x20, InInitializationOrderModuleList -> 0x30
    # DllBase -> 0x30, DllName ->0x48
    CODE = (
        b"  start:                                 "
        b"    push rbp                            ;"
        b"    and rsp, 0fffffffffffffff0h         ;" # Align stack to multiple of 16 bytes
        b"    mov rbp, rsp                        ;" # Function call emulation
        b"    add rsp, 0fffffffffffff9f0h         ;" # Update depending on stack space needed - 610 bytes
        
        b"  find_kernel32:                         "
        b"    xor rbx, rbx                        ;" # EBX = 0
        b"    mov rsi, gs:[rbx+60h]               ;" # ESI = &(PEB)
        b"    mov rsi, [rsi+18h]                  ;" # ESI = PEB->_PEB_LDR_DATA
        b"    mov rsi, [rsi+30h]                  ;" # ESI = PEB->_PEB_LDR_DATA.InInitOrderModList
        
        b"  next_module:                           "
        b"    mov rsi, [rsi]                      ;" # RSI = PEB->_PEB_LDR_DATA.InInitOrderModList.Flink -> module.dll
        b"    mov r8, [rsi+10h]                   ;" # R8 = _LDR_DATA_TABLE_ENTRY->DllBase (module.dll)
        b"    mov rdi, [rsi+40h]                  ;" # RDI = _LDR_DATA_TABLE_ENTRY->FullDllName->Buffer (module.dll)
        b"    cmp [rdi+12*2], cx                  ;" # (Buffer[12] == 0x00) check
        b"    jne next_module                     ;" # If not, jump to start of function
        
        b"  find_func_short:                       "
        b"    jmp find_func_short_2               ;" # Short jump
        
        b"  find_func_return:                      "
        b"    pop rdi                             ;" # POPs return address for find_func from the stack into rdi
        b"    mov [rbp-30h], rdi                  ;" # [RBP-30h] = &find_func
        b"    jmp resolve_kernel32_symbols        ;" 
        
        b"  find_func_short_2:                     "
        b"    call find_func_return               ;" # Negative offset call
        
        b"  find_func:                             "
        b"    mov eax, [r8+3ch]                   ;" # RAX = offset to DOS header->e_lfanew (want lower 8 bytes)
        b"    add rax, r8                         ;" # RAX = &kernel32 + e_lfanew header
        b"    xor rcx, rcx                        ;" # XOR RCX for 0x88 offset calculation (avoiding NULL bytes)
        b"    add rcx, 55h                        ;"
        b"    add rcx, 33h                        ;" # RCX = 0x88
        b"    mov edx, [rax+rcx]                  ;" # RDX = Export Table Directory RVA (want lower 8 bytes)
        b"    add rdx, r8                         ;" # RDX = Export Table Directory VMA
        b"    xor rax, rax                        ;" # RAX = 0
        b"    mov eax, [rdx+20h]                  ;" # EAX = AddressOfNames RVA
        b"    add rax, r8                         ;" # RAX = AddressOfNames VMA
        b"    xor rcx, rcx                        ;" # RCX = 0 for ordinal counter
    
        b"  find_func_loop:                        "
        b"    inc rcx                             ;" # Increment loop counter
        b"    xor rdi, rdi                        ;" # RDI = 0
        b"    mov edi, [rax + rcx * 4]            ;" # RDI = Name offset
        b"    add rdi, r8                         ;" # RDI = Function name
        b"    cmp [rdi], r15                      ;" # Compare function name to "GetProcA"
        b"    jnz find_func_loop                  ;" # If compare fails, go back
        
        b"  func_found:                            " # Function found
        b"    mov esi, [rdx+24h]                  ;" # ESI = AddressOfNameOrdinals RVA
        b"    add rsi, r8                         ;" # RSI = AddressOfNameOrdinals VMA
        b"    mov cx, [rsi+2*rcx]                 ;" # Place function ordinal into CX
        b"    mov ebx, [rdx+1ch]                  ;" # EBX = AddressOfFunctions RVA
        b"    add rbx, r8                         ;" # RBX = AddressOfFunctions VMA
        b"    xor eax, eax                        ;" # EAX = 0
        b"    mov eax, [rbx+rcx*4]                ;" # EAX = function RVA
        b"    add rax, r8                         ;" # RAX = function VMA
        b"    ret                                 ;" # Return
        
        b"  resolve_kernel32_symbols:              "
        b"    mov r15, 0x41636f7250746547         ;" # "AcorPteG" (GetProcA) in ASCII
        b"    call [rbp-30h]                      ;" # Call find_func
        b"    mov [rbp-28h], rax                  ;" # [RBP-28h] = &GetProcAddress
        
        b"  get_loadlibrary_address:               "
        b"    mov rcx, r8                         ;" # RCX = hModule = kernel32.dll address
        b"    mov rax, 41797261h                  ;" # RAX = "Ayra"
        b"    push rax                            ;" # RSP = "Ayra"
        b"    mov rax, 7262694c64616f4ch          ;" # RAX = "rbiLdaoL"
        b"    push rax                            ;" # RSP = "AyrarbiLdaoL"
        b"    mov rdx, rsp                        ;" # RDX = lpProcName = &"AyrarbiLdaoL"
        b"    sub rsp, 20h                        ;" # Allocate stack space for local variables
        b"    call [rbp-28h]                      ;" # GetProcAddress(&kernel32.dll, "LoadLibraryA")
        b"    add rsp, 2ch                        ;" # Clean up stack space after function call
        b"    mov [rbp-20h], rax                  ;" # [RBP-20h] = &LoadLibraryA
        
        b"  get_user32_dll_address:                "
        b"    xor rax, rax                        ;" # RAX = 0
        b"    mov ax, 6c6ch                       ;" # RAX = "ll"
        b"    push rax                            ;" # RSP = "ll"
        b"    mov rax, 642E323372657375h          ;" # RAX = "d.23resu"
        b"    push rax                            ;" # RSP = "lld.23resu"
        b"    mov rcx, rsp                        ;" # RCX = &"lld.23resu"
        b"    sub rsp, 20h                        ;" # Allocate stack space for local variables
        b"    call [rbp-20h]                      ;" # LoadLibraryA("user32.dll")
        b"    add rsp, 20h                        ;" # Clean up stack space after function call
        
        b"  get_MessageBoxA_address:               "
        b"    mov rcx, rax                        ;" # RCX = user32.dll base address
        b"    xor rax, rax                        ;" # RAX = 0
        b"    mov eax, 41786Fh                     ;" # RAX = "Axo"
        b"    push rax                            ;" # RSP = "Axo"
        b"    mov rax, 426567617373654Dh          ;" # RAX = "BegasseM"
        b"    push rax                            ;" # RSP = "AxoBegasseM"
        b"    mov rdx, rsp                        ;" # RDX = &"AxoBegasseM"
        b"    sub rsp, 20h                        ;" # Allocate stack space for local variables 
        b"    call [rbp-28h]                      ;" # GetProcAddress(&user32.dll, "MessageBoxA")
        b"    add rsp, 20h                        ;" # Clean up stack space after function call
        b"    mov r15, rax                        ;" # r15 = &MessageBoxA
        
        b"  call_messageboxa:                      "
        b"    xor rcx, rcx                        ;" # RCX = 0 = hWnd
        b"    xor r9, r9                          ;" # R9 = NULL = uType
        b"    mov rax, 212121214F4F42h            ;"
        b"    push rax                            ;"
        b"    mov rdx, rsp                        ;" # RDX = lpText
        b"    xor rax, rax                        ;" # RAX = 0
        b"    mov eax, 6F5F5F6Fh                  ;"
        b"    push rax                            ;"
        b"    mov r8, rsp                         ;" # R8 = lpCaption
        b"    sub rsp, 2ch                        ;" # Allocate stack space for local variables 
        b"    call r15                            ;" # MessageBoxA()
    )

    try:
        # Initialize engine in 64-bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # asm method returns encoded bytes + number of instructions assembled
        enc, count = ks.asm(CODE)
        #print(enc)
        encoded_sc = b""

        for e in enc:
            # "B" formats enc as an unsigned byte
            encoded_sc += struct.pack("B", e)

        # Returns bytearray of shellcode
        shellcode = bytearray(encoded_sc)

    except KsError as error:
        print("ERROR: %s" % error)

    # PRINT FUNCTIONALITY
    if arg.print:
        printShellcode(enc)

    # DEBUG FUNCTIONALITY
    if arg.debug:
        debug(shellcode)

if __name__ == "__main__":
    main()
