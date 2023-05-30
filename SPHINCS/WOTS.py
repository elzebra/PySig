#################################################################################################
# https://sphincs.org/data/sphincs+-r3.1-specification.pdf
# Section 3. WOTS+ One-Time Signatures
#################################################################################################

import hashlib, random

def XOR(x, y):
    #assert len(x) == len(y)
    n = len(x)
    z = list(x[i]^y[i] for i in range(0, n))
    return bytes(z)

#################################################################################################

## pp = [n, algo, robust, w]
## only supports hash algorithm "shake"

# SecretKey Generation
def PRF(pp, secret_seed, public_seed, addr):
    n = pp[0]; algo = pp[1]
    #assert type(secret_seed) == bytes and len(secret_seed) == n
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(addr) == bytes and len(addr) == 32
    if algo == "shake":
        rand = hashlib.new("shake256", public_seed+addr+secret_seed).digest(n)
    else:
        assert False
    return rand


# Message Randomization
#def Randomize(pp, secret_seed, optional_rand, msg):
#    n = pp[0]; algo = pp[1]
#    #assert type(secret_seed) == bytes and len(secret_seed) == n
#    #assert type(optional_rand) == bytes and len(optional_rand) == n
#    #assert type(msg) == bytes
#    if algo == "shake":
#        rand = hashlib.new("shake256", secret_seed+optional_rand+msg).digest(n)
#    else:
#        assert False
#    return rand


# Message Digest
def MHash(pp, pk, rand, msg):
    n = pp[0]; algo = pp[1];# robust = pp[2]
    w = pp[3]
    #w = pp[5]; h = pp[6]; d = pp[7]
    #assert type(pk) == bytes and len(pk) == 2*n
    #assert type(rand) == bytes and len(rand) == n
    #assert type(msg) == bytes
    #assert w in [4, 8]
    #l0 = (k*a+7)//8  ## FORS Message Size
    #l1 = (h*(d-1)+7)//8
    #l2 = (h+7)//8
    l0 = n
    l1 = 0
    l2 = 0
    l = l0 + l1 + l2
    #print(l0, l1, l2)
    if algo == "shake":
        temp = hashlib.new("shake256", rand+pk+msg).digest(l)
        i = 0
        digest = temp[i:i+l0]; i += l0
        #mt_tree_idx = int.from_bytes(temp[i:i+l1], "big", signed=False) & ((1<<(h*(d-1))) - 1); i += l1
        #mt_leaf_idx = int.from_bytes(temp[i:i+l2], "big", signed=False) & ((1<<h) - 1)
    else:
        assert False
    #return (digest, mt_tree_idx, mt_leaf_idx)
    return digest

# Tweakable Hash for Tree or Chain
def THash(pp, public_seed, addr, node):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(addr) == bytes and len(addr) == 32
    #assert type(node) == bytes and len(node)%n == 0
    if algo == "shake":
        if robust:
            mask = hashlib.new("shake256", public_seed+addr).digest(len(node))
            node = XOR(mask, node)
        digest = hashlib.new("shake256", public_seed+addr+node).digest(n)
    else:
        assert False
    return digest

###############################################################

def MakeAddress(x):
    #assert type(x) == list and len(x) == 6
    y = b""
    y += x[0].to_bytes(4, "big", signed=False)
    y += x[1].to_bytes(12, "big", signed=False)
    y += x[2].to_bytes(4, "big", signed=False)
    y += x[3].to_bytes(4, "big", signed=False)
    y += x[4].to_bytes(4, "big", signed=False)
    y += x[5].to_bytes(4, "big", signed=False)
    return y

def WOTS_Addr_ChainHash(chain_idx, hash_idx, mt_addr=[0, 0, 0]):
    (mt_layer, mt_tree_idx, mt_leaf_idx) = mt_addr
    return MakeAddress([mt_layer, mt_tree_idx, 0, mt_leaf_idx, chain_idx, hash_idx])

def WOTS_Addr_PublicKey(mt_addr=[0, 0, 0]):
    (mt_layer, mt_tree_idx, mt_leaf_idx) = mt_addr
    return MakeAddress([mt_layer, mt_tree_idx, 1, mt_leaf_idx, 0, 0])

def WOTS_Addr_SecretKey(chain_idx, mt_addr=[0, 0, 0]):
    (mt_layer, mt_tree_idx, mt_leaf_idx) = mt_addr
    return MakeAddress([mt_layer, mt_tree_idx, 5, mt_leaf_idx, chain_idx, 0])

###############################################################

#n = 16, 24, 32
#w = 4, 8

def WOTS_PreprocessMessage(pp, pk, rand, msg):
    n = pp[0]; #algo = pp[1]; robust = pp[2]
    w = pp[3]
    
    (public_seed, public_root) = pk
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(public_root) == bytes and len(public_root) == n
    public_key = public_seed + public_root
    hashed_msg = MHash(pp, public_key, rand, msg)

    assert type(hashed_msg) == bytes and len(hashed_msg) == n
    assert n in [16, 24, 32] and w in [4, 8]
    l1 = n*(8//w)
    l2 = 3 if w == 4 else 2
    l = l1 + l2
    #print(n, w, l1, l2, l)
    values = list()
    s = 0
    for i in range(0, l1):
        if w == 16:
            v = hashed_msg[i]
        else:
            v = hashed_msg[i//2]
            v = v//16 if i%2 == 0 else v%16
        s += (2**w) - 1 - v
        values.append(v)
    #print(s)
    for i in range(0, l2):
        v = s//(2**((l2-1-i)*w))
        s = s%(2**((l2-1-i)*w))
        values.append(v)
    assert len(values) == l
    #print(values)
    return values

def WOTS_GeneratePublicKey(pp, secret_seed, public_seed=None, mt_addr=[0, 0, 0]):
    n = pp[0]; #algo = pp[1]; robust = pp[2]
    w = pp[3]
    
    if public_seed == None:
        public_seed = random.randbytes(n)
    
    assert type(secret_seed) == bytes and len(secret_seed) == n
    assert type(public_seed) == bytes and len(public_seed) == n
    assert n in [16, 24, 32] and w in [4, 8]
    l1 = n*(8//w)
    l2 = 3 if w == 4 else 2
    l = l1 + l2
    #print(n, w, l1, l2, l)
    
    nodes = list()
    for i in range(0, l):
        #print("-"*100)
        addr = WOTS_Addr_SecretKey(i, mt_addr)
        node = PRF(pp, secret_seed, public_seed, addr)
        #print(len(addr), addr.hex())
        #print(len(node), node.hex())

        for j in range(0, (2**w) - 1):
            addr = WOTS_Addr_ChainHash(i, j, mt_addr)
            node = THash(pp, public_seed, addr, node)
        nodes.append(node)
        #print(len(addr), addr.hex())
        #print(len(node), node.hex())

    addr = WOTS_Addr_PublicKey(mt_addr)    
    public_root = THash(pp, public_seed, addr, b"".join(nodes))
    #print(len(addr), addr.hex())
    #print(len(public_root), public_root.hex())
    return (public_seed, public_root)

def WOTS_Sign(pp, secret_seed, pk, msg, rand=None, mt_addr=[0, 0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    w = pp[3]
    (public_seed, public_root) = pk
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(secret_seed) == bytes and len(secret_seed) == n
    #assert type(msg) == bytes

    if rand == None:
        rand = random.randbytes(n)
    #assert type(rand) == bytes and len(rand) == n
    values = WOTS_PreprocessMessage(pp, pk, rand, msg)
    l1 = n*(8//w)
    l = len(values)
    l2 = l - l1
    print(n, w, l1, l2, l)
    
    sigs = list()
    for i in range(0, l):
        #print("-"*100)
        addr = WOTS_Addr_SecretKey(i, mt_addr)
        node = PRF(pp, secret_seed, public_seed, addr)
        #print(len(addr), addr.hex())
        #print(len(node), node.hex())

        for j in range(0, values[i]):
            addr = WOTS_Addr_ChainHash(i, j, mt_addr)
            node = THash(pp, public_seed, addr, node)
        sigs.append(node)
        #print(len(addr), addr.hex())
        #print(len(node), node.hex())
    return (rand, sigs)


def WOTS_Verify(pp, pk, signature, msg, mt_addr=[0, 0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    w = pp[3]
    (public_seed, public_root) = pk
    (rand, sigs) = signature
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(public_root) == bytes and len(public_root) == n
    #assert type(msg) == bytes
    #assert type(rand) == bytes and len(rand) == n
    
    values = WOTS_PreprocessMessage(pp, pk, rand, msg)
    #assert len(values) == k
    #print(values)
    assert len(values) == len(sigs)
    l1 = n*(8//w)
    l = len(values)
    l2 = l - l1
    #print(n, w, l1, l2, l)
    
    nodes = list()
    for i in range(0, l):
        #print("-"*100)
        node = sigs[i]
        assert type(node) == bytes and len(node) == n
        #print(len(addr), addr.hex())
        #print(len(node), node.hex())

        for j in range(values[i], (2**w) - 1):
            addr = WOTS_Addr_ChainHash(i, j, mt_addr)
            node = THash(pp, public_seed, addr, node)
        nodes.append(node)
        #print(len(addr), addr.hex())
        #print(len(node), node.hex())

    addr = WOTS_Addr_PublicKey(mt_addr)    
    public_root1 = THash(pp, public_seed, addr, b"".join(nodes))
    #print(len(addr), addr.hex())
    print(len(public_root1), public_root1.hex())
    return public_root == public_root1
