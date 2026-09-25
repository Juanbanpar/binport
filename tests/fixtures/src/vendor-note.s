.section .note.vendor,"",@note
/* Four-byte note framing, but no section address-alignment constraint.
   Explicit padding keeps sh_addralign=1 instead of raising it with .balign. */
.long 5, 1, 1
.asciz "ACME"
.byte 0, 0, 0
.byte 42, 0, 0, 0
.section .note.GNU-stack,"",@progbits
