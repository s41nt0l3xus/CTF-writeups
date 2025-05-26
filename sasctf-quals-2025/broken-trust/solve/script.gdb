target remote :31338
add-symbol-file ./server-user/app/tee.elf
b *syscall_sas+140
b *syscall_sas+212
b *syscall_sas+280
b *sas_do_smc_healthcheck
