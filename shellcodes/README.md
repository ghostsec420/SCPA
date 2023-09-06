# Shellcodes

## Summary

Shellcodes are a sequence of bytes that includes a payload (a command, a shell, etc.),

Shellcodes is composed as follows :

- Recon of the target (if it uses `NX Mitigation` or the old rights `RWX`)
- If it uses `NX Mitigation`, use `mprotect` or `mmap` to find a `RWX` rights area (ROP, fouling of `ebp`, and `eip`)
- Development in Assembly (architecture to define)
- At least one section (`.text`)
- Reduce the number of instructions to be quiet
- The register `rax` (int64) or `eax` (int32) should be used to set to a sys (cf. syscall markdowns)
- `rax` or `eax` should be `mov` with a `sys_execve` (`59` for `rax`, `11` for `eax`)
- You have to set the register `rdi` to `<command>` (by a `mov` to command address)
- You have to initialize by a `xor` (to bypass `\0`, `\n`, or `\x20` which blocks the ROP) the registers `rsi` and `rdx`, and add a `/` to the command to remove other `NULL bytes`
- Set a `syscall` at the end of the section (Userland -> libc -> Ring 0)
- Compile and disassemble (to see if there is not `NULL bytes` and if it's usable) :
    ```bash
    nasm -f <bin32/64> shellcode.s -o shellcode.o
    ld shellcode.o -o shellcode
    objdump -d -Mintel ./shellcode
    ```
- Integration to an exploit (with bytes as `\x`)

## Summary (RISC-V particularities)

// tbc
