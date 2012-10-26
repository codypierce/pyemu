## ia32 opcode tables - thx to sandpile.org and a little bit of alcohol
## (that also means that this potentially will contain errors)

opcode_1 = '''
add Eb, Gb
add Ev, Gv
add Gb, Eb
add Gv, Ev
add al, Ib
add rAX, Iz
push es
pop es
or Eb, Gb
or Ev, Gv
or Gb, Eb
or Gv, Ev
or al, Ib
or rAX, Iz
push cs
>opcode_2

# 0x10
adc Eb, Gb
adc Ev, Gv
adc Gb, Eb
adc Gv, Ev
adc al, Ib
adc rAX, Iz
push ss
pop ss
sbb Eb, Gb
sbb Ev,Gv
sbb Gb,Eb
sbb Gv,Ev
sbb al, Ib
sbb rAX,Iz
push ds
pop ds

# 0x20
and Eb,Gb
and Ev,Gv
and Gb,Eb
and Gv,Ev
and al, Ib
and rAx, Iz
es:
daa
isub Eb,Gb
sub Ev,Gv
sub Gb,Eb
sub Gv,Ev
sub al, Ib
sub rAX,Iz
cs:
das

# 0x30
xor Eb,Gb
xor Ev,Gv
xor Gb,Eb
xor Gv,Ev
xor al,Ib
xor rAX,Iz
ss:
aaa
cmp Eb,Gb
cmp Ev,Gv
cmp Gb,Eb
cmp Gv,Ev
cmp al,Ib
cmp rAX,Iz
ds:
aas

# 0x40
inc eAX
inc eCX
inc eDX
inc eBX
inc eSP
inc eBP
inc eSI
inc eDI
dec eAX
dec eCX
dec eDX
dec eBX
dec eSP
dec eBP
dec eSI
dec eDI

# 0x50
push rAX
push rCX
push rDX
push rBX
push rSP
push rBP
push rSI
push rDI
pop rAX
pop rCX
pop rDX
pop rBX
pop rSP
pop rBP
pop rSI
pop rDI

# 0x60
pusha (80186+)
popa (80186+)
bound Gv,Ma (80186+)
arpl Ew,Gw (80286+)
fs: (80386+)
gs: (80387+)
opsize: (80386+)
adsize: (80386+)
push Iz (80186+)
imul Gv,Ev,Iz (80186+)
push Ib (80186+)
imul Gv,Ev,Ib (80186+)
ins Yb, DX (80186+)
ins Yz, DX (80186+)
outs DX, Xb (80186+)
outs DX,Xz (80186+)

# 0x70
jo Jb
jno Jb
jb Jb
jnb Jb
jz Jb
jnz Jb
jbe Jb
jnbe Jb
js Jb
jns Jb
jp Jb
jnp Jb
jl Jb
jnl Jb
jle Jb
jnle Jb

#0x80
group_1 Eb,Ib
group_1 Ev,Iz
group_1 Eb,Ib
group_1 Ev,Ib
test Eb,Gb
test Ev,Gv
xchg Eb,Gb
xchg Ev,Gv
mov Eb, Gb
mov Eb,Gv
mov Gb,Eb
mov Gv,Ev
mov Mw,Sw
lea Gv,M
mov Sw,Mw
group_10

#0x90
nop
xchg rCX,rAX
xchg rDX,rAX
xchg rBX,rAX
xchg rSP,rAX
xchg rBP,rAX
xchg rSI,rAX
xchg rDI, rAX
cbw (8088) cwde (80386+)
cwd (8088) cdq (80386+)
call Ap
wait () fwait ()
pushf Fv
popf fv
sahf
lahf

#0xa0
mov al, Ob
mov rAX, Ov
mov Ob, al
mov Ov, rAX
movs Yb,Xb
movs Yv,Xv
cmps Yb,Xb
cmps Yv,Xv
test al, Ib
test rAX,Iz
stos Yv,al
stos Yv,rAx
lods al, Xb
lods rAX,Xv
scas Yb,al
scas Yv,rAx

#0xb0
mov al, Ib
mov cl, Ib
mov dl,Ib
mov bl,Ib
mov ah,Ib
mov ch,Ib
mov dh,Ib
mov bh,Ib
mov rAX,Iv
mov rCX,Iv
mov rDX,Iv
mov rBX,Iv
mov rSP,Iv
mov rBP,Iv
mov rSI,Iv
mov rDI,Iv

#0xc0
group_2 Eb,Ib (80186+)
group_2 Ev,Ib (80186+)
retn Iw
retn
les Gz,Mp
lds Gz,Mp
group_11 Eb,Ib
group_11 Ev,Iz
enter Iw,Ib (80186+)
leave (80186+)
retf Iw
retf
int3
int Ib
into
iret

#0xd0
group_2 Eb, 1
group_2 Ev, 1
group_2 Eb,CL
group_2 Ev,CL
aam Ib
aad Ib
salc () setalc ()
xlat
esc 0
esc 1
esc 2
esc 3
esc 4
esc 5
esc 6
esc 7

#0xe0
loopnz Jb () loopne Jb ()
loopz Jb () loope Jb ()
loop Jb
jcxz Jb () jecx Jb ()
in al, Ib
in eAX, Ib
out Ib, al
out Ib, eAX
call Jz
jmp Jz
jmp Ap
jmp Jb
in al, dx
in eAX, dx
out dx,al
out dx, eAX

#f0
lock:
int1 () icebp (80386+)
repnz: () repne: ()
repz: () rep: () repe: ()
hlt
cmc
group_3 Eb
group_3 Ev
clc
stc
cli
sti
cld
std
group_4   Eb    # inc/dec
group_5   Ev    # inc/dec etc.
'''

group_1 = '''
add
or
adc
sbb
and
sub
xor
cmp
'''

group_2 = '''
rol
ror
rcl
rcr
shl
shr
sal
sar
'''

group_3 = '''
test Ib
test Iz
not
neg
mul rAX
imul rAX
div rAX
idiv rAX
'''

group_4 = '''
inc Eb
dec Eb
'''

group_5 = '''
inc Ev
dec Ev
call Ev
call Mp
jmp Ev
jmp Mp
push Ev
'''

### XXX: this doesn't look right...
group_6 = '''
sldt Mw () sldt Rv ()
str Mw () str Rv ()
lldt Mw () lldt Rv ()
ltr Mw () ltr Rv ()
verr Mw () verw Rv ()
verw Mw () verw Rv ()
jmpe Ev (IA-64)
'''

group_7 = '''
sgdt Ms
sidt Ms
lgdt Ms
lidt Ms
smsw Mw
-
lmsw Mw
invlpg M (80486+)
'''


group_8 = '''
-
-
-
-
bt
bts
btr
btc
'''

### XXX: it looks like we'll need to provide a property of an opcode
group_9 = '''
-
cmpxchg Mq
-
-
-
-
vmptrld Mq
vmptrst Mq
'''

group_10 = '''
pop Ev
'''

# XXX: tbh, these tables are inaccurate due to lack of foresight on my part
#      and i'm tired of typing...
opcode_2 = '''
group_6
group_7
lar Gv,Ew
lsl Gv,Ew
-
syscall
clts
sysret
-
-
-
-
-
-
-
-

# 0x10
movups Vp, Wp
movups Wp, Vp
movlps Vp, Mq () movhlps Vp,Vq ()
movlps Mq, Vp
unpcklps Vp, Wq
unpckhps Vp,Wq
movhps Vps,Mq () movlhps Vp,Wp ()
-
cmovs Gv,Ev
cmovns Gv,Ev
cmovp Gv,Ev
cmovnp Gv,Ev
cmovl Gv,Ev
cmovnl Gv,Ev
cmovle Gv,Ev
cmovnle Gv,Ev

# 0x20
mov Rd, Cd
mov Rd, Dd
mov Cd, Rd
mov Dd, Rd
-
-
-
-
movaps Vp,Wp
movaps Wp,Vp
cvtpi2ps Vp,Qq
movntps Md,Vp
cvttps2pi Pq,Wp
cvtps2pi Pq,Wp
ucomiss Vs,Ws
comiss Vp,Wp

# 0x30
wrmsr
rdtsc
rdmsr
rdpmc
sysenter
sysexit
-
-
-
-
-
-
-
-
-
-

# 0x40
cmovo Gv,Ev
cmovno Gv,Ev
cmovb Gv,Ev
cmovnb Gv,Ev
cmovz Gv,Ev
cmovnz Gv,Ev
cmovbe Gv,Ev
cmovnbe Gv,Ev
cmovs Gv,Ev
cmovns Gv,Ev
cmovp Gv,Ev
cmovnp Gv,Ev
cmovl Gv,Ev
cmovnl Gv,Ev
cmovle Gv,Ev
cmovnle Gv,Ev

# 0x50
movmskps Gd, Vp
sqrtps Vp,Wp
rsqrtps Vp,Wp
rcpps Vp,Wp
andps Vp,Wp
andnps Vp,Wp
orps Vp,Wp
xorps Vp,Wp
addps Vp,Wp
mulps Vp,Wp
cvtps2pd Vp,Wp
cvtdq2ps Vp,Wd
subps Vp,Wp
minps Vp,Wp
divps Vp,Wp
maxps Vp,Wp

# 0x60
punpcklbw Pq,Qd
punpcklwd Pq,Qd
punpckldq Pq,Qd
packsswb Pq,Qq
pcmpgtb Pq,Qq
pcmpgtw Pq,Qq
pcmpgtd Pq,Qq
packuswb Pq,Qq
punpckhbw Pq,Qd
punpckhwd Pq,Qd
punpckhdq Pq,Qd
packssdw Pq,Qq
-
-
movd Pq, Ed
movq Pq, Qq

# 0x70
pshufw Pq,Qq,Ib
group_12
group_13
group_14
pcmpeqb Pq,Qq
pcmpeqw Pq,Qq
pcmpeqd Pq,Qq
emms
-
-
-
-
-
-
movd Ed,Pd
movq Qq,Pq

# 0x80
jo Jz
jno Jz
jb Jz
jnb Jz
jz Jz
jnz Jz
jbe Jz
jnbe Jz
js Jz
jns Jz
jp Jz
jnp Jz
jl Jz
jnl Jz
jle Jz
jnle Jz

# 0x90
seto Eb
setno Eb
setb Eb
setnb Eb
setz Eb
setnz Eb
setbe Eb
setnbe Eb
sets Eb
setns Eb
setp Eb
setnp Eb
setl Eb
setnl Eb
setle Eb
setnle Eb

#0xa0
push fs
pop fs
cpuid
bt Ev,Gv
shld Ev,Gv,Ib
shld Ev,Gv,cl
-
-
push gs
pop gs
rsm
bts Ev,Gv
shrd Ev,Gv,Ib
shrd Ev,Gv,cl
group_15
imul Gv,Ev

# 0xb0
cmpxchg Eb,Gb
cmpxchg Ev,Gv
lss Gz,Mp
btr Ev,Gv
lfs Gz,Mp
lgs Gz,Mp
movzx Gv,Eb
movzx Gv,Ew
popcnt Gv,Ev    # requires 0xf3
group_10
group_8 Ev,Ib
btc Ev,Gv
bsf Gv,Ev
bsr Gv,Ev
movsx Gv,Eb
movsx Gv,Ew

#0xc0
xadd Eb,Gb
xadd Ev,Gv
cmpps Vp,Wp,Ib
movnti Md,Gd
pinsrw Pq,Eq,Ib
pextrw Gd,Pq,Ib
shufps Vp,Wp,Ib
group_9 Mq
bswap rAX
bswap rCX
bswap rDX
bswap rBX
bswap rSP
bswap rBP
bswap rSI
bswap rDI

# 0xd0
addsubpd Vp,Wp  #requires 0x66
psrlw Pq,Qq
psrld Pq,Qq
psrlq Pq,Qq
paddq Pq,Qq
pmullw Pq,Qq
movq Vd, Pq     # requires 0x66
-
psubusb Pq,Qq
psubusw Pq,Qq
pminub Pq,Qq
pand Pq,Qq
paddusb Pq,Qq
paddusw Pq,Qq
pmaxub Pq,Qq
andn Pq,Qq

#0xe0
pavgb Pq,Qq
psraw Pq,Qq
psrad Pq,Qq
pavgw Pq,Qq
pmulhuw Pq,Qq
pmulhw Pq,Qq
-
movnq Mq,Pq
psubsb Pq,Qq
psubsw Pq,Qq
pminsw Pq,Qq
por Pq,Qq
paddsb Pq,Qq
paddsw Pq,Qq
pmaxsw Pq,Qq
pxor Pq,Qq

# 0xf0
lddqu Vp,Md
psllw Pq,Qq
pslld Pq,Qq
psllq Pq,Qq
pmuludq Pq,Qq
pmaddwd Pq,Qq
psadbw Pq,Qq
maskmovq Pq,Pq
psubb Pq,Qq
psubw Pq,Qq
psubd Pq,Qq
psubq Pq,Qq
paddb Pq,Qq
paddw Pq,Qq
paddd Pq,Qq
-
'''

### this is the main table we export
table = {
    'opcode_1' : opcode_1,
    'opcode_2' : opcode_2,
    'group_1' : group_1,
    'group_2' : group_2,
    'group_3' : group_3,
    'group_4' : group_4,
    'group_5' : group_5,
    'group_6' : group_6,
    'group_7' : group_7,
    'group_8' : group_8,
    'group_9' : group_9,
    'group_10' : group_10,
}
