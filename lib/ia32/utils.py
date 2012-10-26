def assert_exc(cond, exception, *args):
    '''raise an exception given a provided test'''
    if not cond():
        raise exception(*args)
    return

class prop(dict):
    def __setitem__(self, k, v):
        assert_exc( lambda : k in self.keys(), KeyError, k  )
        return super(prop, self).__setitem__(k, v)

    '''
    test 1:
    v = prop()
    print v
    test 2:
    print v[5]
    test 3:
    v[5] = 10
    print v

    test 1:
    v = prop([(5, 1)])
    print v
    test 2:
    print v[5]
    test 3:
    v[5] = 10
    print v
    test 4:
    print v[6]
    test 5:
    v[6] = 5
    '''
