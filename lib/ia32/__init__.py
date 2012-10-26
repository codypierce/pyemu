from parse import parse
from data import table
from utils import prop

# pre-parse all of our tables
table = dict([(k,parse(v)) for k,v in table.items()])

def sib(val):
    "(scale, index, base)"
    res = ord(val)
    return ((res&0xc0) >> 6, (res&0x38) >> 3, (res&7) >> 0)

modrm=sib
modrm.__doc__ = "mod / reg / r/m"

### quick lookup tables
optable = table['opcode_1']
optable = dict([ (i, v) for i,v in zip(range(len(optable)), optable) ])
prefix = [k for k,v in optable.items() if v[0] == ':' ]

###
def decode(s):
    '''given an iterable s, return the next valid instruction'''
    s = iter(s)
    size = 0
    keys = 'prefix opcode modrm sib disp imm size'.split(' ')
    res = prop([(k, None) for k in keys])
    res['prefix'] = []

    ## prefixes
    for x in range(4):
        v = s.next()
        size += 1
        if ord(v) in prefix:
            res['prefix'].append(v)
            continue
        break

    ## rex prefixes
    # j/k

    ## opcode
    row = optable[ ord(v) ]

    opcode = str(v)
    if row[0] == '>':
        tbl = table[row[1]]
        v = s.next()
        row = tbl[ ord(v) ]
        opcode += v

    args = row[2]
    res['opcode'] = opcode

    ## modrm / sib
    if args['modrm']:
        res['modrm'] = s.next()
        mod,reg,rm = modrm(res['modrm'])
        size += 1

        if mod < 3 and rm == 4:
            res['sib'] = True

        if mod == 0 and rm == 5:
            res['disp'] = 4

        if mod == 1:
            res['disp'] = 1

        if mod == 2:
            res['disp'] = 4

    if res['sib']:
        res['sib'] = s.next()
        size += 1

    ## displacement
    if res['disp']:
        length = res['disp']
        res['disp'] = ''.join([x for i,x in zip(range(length), s)])
        size += length

    ## immediate
    if args['imm']:
        length = args['length']( 0x66 not in res['prefix'] )
        res['imm'] = ''.join([x for i,x in zip(range(length), s)])
        size += length

    res['size'] = size
    return res

if __name__ == '__main__':
    def hex(num):
        return '%x'% num

    '''
    804876b:       55                      push   %ebp
    804876c:       89 e5                   mov    %esp,%ebp
    804876e:       83 ec 08                sub    $0x8,%esp
    8048771:       a1 48 26 05 08          mov    0x8052648,%eax
    8048776:       85 c0                   test   %eax,%eax
    8048778:       74 12                   je     804878c <read@plt+0xac>
    804877a:       b8 00 00 00 00          mov    $0x0,%eax
    804877f:       85 c0                   test   %eax,%eax
    8048781:       74 09                   je     804878c <read@plt+0xac>
    8048783:       c7 04 24 48 26 05 08    movl   $0x8052648,(%esp)
    804878a:       ff d0                   call   *%eax
    804878c:       c9                      leave
    804878d:       c3                      ret
    '''

    code = "55 89 e5 83 ec 08 a1 48 26 05 08 85 c0 74 12 b8 00 00 00 00 85 c0 74 09 c7 04 24 48 26 05 08 ff d0 c9 c3"
    code = ''.join([chr(int(x,16)) for x in code.split(' ')])

    s = iter(code)
    res = 'size prefix opcode modrm sib disp imm'.split(' ')
    print '\t'.join(res)
    while True:
        v = decode(s)
        res = []
        res.append( repr(v['size']) )
        res.append( repr([hex(ord(x)) for x in v['prefix']]) )
        res.append( repr(v['opcode']) )
        res.append( repr(v['modrm']) )
        res.append( repr(v['sib']) )
        res.append( repr(v['disp']) )
        res.append( repr(v['imm']) )
        print '\t'.join(res)

