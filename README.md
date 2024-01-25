# WardenREKT
Ready to pasta

## Funcs
- Restore all int3 -> NOP hooks set by Warden
- As their entire exception handler is set by KiUserExceptionDispatcher memory region, we can simply turn it off and NOP the bytes
- By disabling function hooks or restoring them, we place a 0xCC or 0xC3 opcode instead and overlap the existent memory

## Todo
- Remove CE protect (Warden AC has pasted their CE detection from HALO Infinite; they place a callback to get all DbgPrint logs and check which one matches with CE as they have a blacklist)
- Use hde64 for auto scan AOB within proc
- Hook the VEH directly and place our custom exceptions from there
- Restore string encryption and function obfuscation routines using UNICORN Engine directly in process, and save dump to .exe
