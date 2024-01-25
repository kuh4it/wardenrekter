# WardenREKT
Ready to pasta

## Funcs
- Restore all int3 -> NOP hooks set by Warden
- As their entire exception handler is set by KiUserExceptionDispatcher memory region, we can simply turn it off and NOP the bytes

## Todo
- Remove CE protect
- Use hde64 for auto scan AOB within proc
