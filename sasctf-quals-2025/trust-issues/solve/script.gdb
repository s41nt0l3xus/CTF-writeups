target remote :1234
add-symbol-file ./task/41414141-7472-7573-745f-697373756573.elf 0x117000
b *run_code
b *run_code_cmd+314
