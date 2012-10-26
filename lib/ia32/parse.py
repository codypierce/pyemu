from utils import prop

### XXX: this whole thing is such a horrible hack

### note: i stopped caring about this code about 10% through.
###       it originated from a poc of doing a prop-lookup
###       based disassembler using non-table based input. that
###       way me and my gf can type in data mindlessly.

def tokens(iterable):
    iterable = iter(iterable)
    res = ''

    try:
        while True:
            ch = iterable.next()

            if ch in ', \t()\n>:#':
                if res:
                    yield res
                    res = ''
                yield ch

            else:
                res += ch

    except StopIteration:
        if res:
            yield res

def pfactory(**kwds):
    keys = 'length modrm imm reg'.split(' ')
    res = prop([(k, None) for k in keys])

    for k,v in kwds.items():
        res[k] = v

    return res

class reglookup:
    'lookup table for identifying reg'
    r8 = 'al cl dl bl ah ch dh bh'.split(' ')
    r16 = 'ax cx dx bx sp bp si di'.split(' ')
    r32 = 'eax ecx edx ebx esp ebp esi edi'.split(' ')
    mm = 'mm0 mm1 mm2 mm3 mm4 mm5 mm6 mm7'.split(' ')
    xmm = 'xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7'.split(' ')
    sreg = 'es cs ss ds fs gs res1 res2'.split(' ')
    cr = 'cr0 cr1 cr2 cr3 cr4 cr5 cr6 cr7'.split(' ')
    dr = 'dr0 dr1 dr2 dr3 dr4 dr5 dr6 dr7'.split(' ')

opencoding = dict([
    ( 'A', pfactory(imm=True) ),
    ( 'C', pfactory(reg=reglookup.cr) ),
    ( 'D', pfactory(reg=reglookup.dr) ),
    ( 'E', pfactory(modrm=True) ),
    ( 'F', pfactory() ),
    ( 'G', pfactory(modrm=True) ),
    ( 'I', pfactory(imm=True) ),
    ( 'J', pfactory(imm=True) ),
    ( 'M', pfactory(modrm=True) ),
    ( 'O', pfactory(imm=True) ),
    ( 'P', pfactory(modrm=True, reg=reglookup.mm) ),
    ( 'Q', pfactory(modrm=True, reg=reglookup.mm) ),
    ( 'R', pfactory(modrm=True) ),
    ( 'S', pfactory(modrm=True, reg=reglookup.sreg) ),
#    ('T', pfactory() ), #XXX: what's this for?
    ( 'V', pfactory(modrm=True, reg=reglookup.xmm) ),
    ( 'X', pfactory() ),
    ( 'Y', pfactory() )
])

opsize = dict([
    ('b', lambda x: 1),
    ('w', lambda x: 2),
    ('d', lambda x: 4),
    ('q', lambda x: 8),
    ('o', lambda x: 16),
    ('v', lambda x: [2, 4][x]), # opsize
    ('z', lambda x: [2, 4][x]), # opsize
    ('a', lambda x: [4, 8][x]),
    ('p', lambda x: [4, 6][x]),
    ('s', lambda x: 6),
    ('t', lambda x: 10),
    ('z', lambda x: [2, 4][x])
])

def parse_arg(arg):
    try:
        encoding = arg[0]
        size = arg[1]

        res = opencoding[encoding]
        res['length'] = opsize[size]

    except IndexError:
        return pfactory()

    except KeyError:
        return pfactory()
        
    return res

def parse_args(args):
    res = pfactory()
    for value in args:
        dct = parse_arg(value)

        for k,v in dct.items():
            if v is not None:
                res[k] = v

    return res

#    op = "mnemonic", "arguments" ","
class ParseError(Exception): pass

## first pass to remove comments and ensure constraints are wrapped in ()
# ...if only i wasn't self taught, this might look better..... :(
def parse_firstpass(iterable):
    token = tokens(iterable)

    res = []    # our token stack
    inparen = 0

    def reset():
        assert inparen == 0, "Parentheses in '%s' is not closed"% repr(res)
        original = list(res)
        if res:
            del(res[:])
        return original

    try:
        while True:
            t = token.next()
            assert len(t) > 0, 'len("%s") <= 0'% repr(t)

            # formatting tokens
            if len(t) == 1:
                # whitespace
                if (t in ' \t'):
                    continue

                # newline
                if t == '\n':
                    x = reset()
                    if x:
                        yield x
                    continue

                # comments
                if t == '#':
                    if res:
                        x = reset()
                        if x:
                            yield x

                    v = token.next()
                    while v != '\n':
                        v = token.next()

                    continue

            # catch-all
            if inparen > 0:
                if t == '(':
                    inparen += 1
                    raise ParseError("recursive '(' not allowed")

                if t == ')':
                    inparen -= 1
                    res[-1] += ')'
                    continue

                res[-1] += t
                continue

            if inparen == 0:
                if t == ')':
                    raise ParseError("terminating ')' without an opening '('")

                if t == '(':
                    inparen += 1
                    res.append(t)
                    continue

                res.append(t)
                continue

    except StopIteration:
        if res:
            x=reset()
            if x:
                yield x
    return

def isConstraint(s):
    'return True if s is wrapped in "()"'
    return s.startswith('(') and s.endswith(')')

# collects opcode index, associates operand properties with operands, etc
def parse_insn(row):
    'parses an instruction row'
    insn = ""; index = 0
    res = []; args = []; constraint = "()"
    for col in row:
        if not insn:
            insn = col
            continue

        if isConstraint(col):
            constraint = col
            res.append( ('.', insn, parse_args(args), constraint) )
            insn = ''; args = []
            constraint = '()'
            index = 0
            continue

        if index&1 == 0:
            args.append(col)
            index += 1
            continue

        if col != ',':
            raise ParseError("Expected ','")
        index += 1

    if insn:
        res.append( ('.', insn, parse_args(args), '()') )
    return res

def parse_redirect(row):
    'parses a redirect row (">")'
    gt = row.pop(0)
    table = row.pop(0)

    constraint = '()'
    args = []
    index = 0
    for col in row:
        
        if isConstraint(col):
            constraint = col

        elif index&1 == 0:
            if col == ',':
                raise ValueError("Unexpected ','")

            args.append(col)

        elif col != ',':
            raise ValueError("Expected a ','")

        index += 1

    return [('>', table, parse_args(args), constraint)]

def parse_prefix(row):
    'parse a prefix row (":")'
    res = []
    prefix = ""
    for col in row:
        if col == ":":
            continue

        if isConstraint(col):
            res.append( (":", prefix, parse_args([]), col) )
            prefix = ""
            continue

        if prefix != "":
            raise ParseError("Only allowed to specify 1 prefix")
        prefix = col

    if prefix:
        res.append( (":", prefix, parse_args([]), "()") )
    return res

def parse_row(row):
    'parse a row, and branch to the correct parsing function'
    if row[0] == '>':
        return parse_redirect(row)
    if len(row) > 1 and row[1] == ':':
        return parse_prefix(row)
    return parse_insn(row)

def parse_secondpass(iterable):
    iterable = iter(iterable)
    linenum = 0
    while True:
        line = iterable.next();
        linenum += 1
        try:
            yield parse_row(line)[0]

        except Exception, e:
            raise ParseError('Error parsing line %d "%s"->\n    %s: %s'% (linenum, line, e.__class__.__name__, str(e)))

def parse(table):
    res = parse_firstpass(table)
    res = parse_secondpass(res)
    return list(res)

if __name__ == '__main__':
    from data import opcode_1,opcode_2

    table = parse(opcode_1)
    table = dict([ (i, v) for i,v in zip(range(len(table)), table) ])
    print table

    table = parse(opcode_2)
    table = dict([ (i, v) for i,v in zip(range(len(table)), table) ])
    print table
