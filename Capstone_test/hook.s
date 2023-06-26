.global myAssemblyFunction

.text
_hook_ret:
    add $10, %rax  # Add 10 to the value in the rax register
    ret
