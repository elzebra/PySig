import hashlib, random

def XOR(x, y):
    #assert len(x) == len(y)
    n = len(x)
    z = list(x[i]^y[i] for i in range(0, n))
    return bytes(z)

#################################################################################################

## pp = [n, algo, robust, k, a]

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
    k = pp[3]; a = pp[4]
    #w = pp[5]; h = pp[6]; d = pp[7]
    #assert type(pk) == bytes and len(pk) == 2*n
    #assert type(rand) == bytes and len(rand) == n
    #assert type(msg) == bytes
    l0 = (k*a+7)//8  ## FORS Message Size
    #l1 = (h*(d-1)+7)//8
    l1 = 0
    #l2 = (h+7)//8
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

def FORS_Addr_TreeHash(height, leaf_idx, mt_addr=[0, 0, 0]):
    (mt_layer, mt_tree_idx, mt_leaf_idx) = mt_addr
    return MakeAddress([mt_layer, mt_tree_idx, 3, mt_leaf_idx, height, leaf_idx])

def FORS_Addr_PublicKey(mt_addr=[0, 0, 0]):
    (mt_layer, mt_tree_idx, mt_leaf_idx) = mt_addr
    return MakeAddress([mt_layer, mt_tree_idx, 4, mt_leaf_idx, 0, 0])

def FORS_Addr_SecretKey(leaf_idx, mt_addr=[0, 0, 0]):
    (mt_layer, mt_tree_idx, mt_leaf_idx) = mt_addr
    return MakeAddress([mt_layer, mt_tree_idx, 6, mt_leaf_idx, 0, leaf_idx])

###############################################################

def FORS_PreprocessMessage(pp, pk, rand, msg):
    n = pp[0]; #algo = pp[1]; robust = pp[2]
    k = pp[3]; a = pp[4]
    
    (public_seed, public_root) = pk
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(public_root) == bytes and len(public_root) == n
    pk = public_seed + public_root
    hashed_msg = MHash(pp, pk, rand, msg)
    
    assert type(hashed_msg) == bytes and len(hashed_msg) >= (k*a+7)//8
    #assert n in [16, 24, 32]
    t = 2**a
    #print(n, k, a, t)
    
    #x = str()
    #for i in range(0, len(hashed_msg)):
    #    x += f"{hashed_msg[i]:08b}"
    #print(x)
    #assert len(x) >= k*a
    
    values = list()
    i = 0
    while len(values) < k:
        v = 0
        for j in range(0, a):
            v ^= ((hashed_msg[i//8] >> (i%8)) & 1) << j
            i += 1
        values.append(v)
    assert len(values) == k
    return values

def FORS_TreeHash(pp, secret_seed, public_seed, tree_idx, height, node_idx, mt_addr=[0, 0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    k = pp[3]; a = pp[4]

    assert tree_idx >= 0 and tree_idx < k
    assert height >= 0 and height <= a
    assert node_idx >= 0 and node_idx < (2**(a-height))
    #leaf_index = tree_index*(2**a) + node_index
    leaf_idx = tree_idx*(2**(a-height)) + node_idx
    
    if height == 0:
        addr = FORS_Addr_SecretKey(leaf_idx, mt_addr)
        #print(len(addr), addr.hex())
        parent = PRF(pp, secret_seed, public_seed, addr)
        #print(len(parent), parent.hex())
    else:
        left = FORS_TreeHash(pp, secret_seed, public_seed, tree_idx, height-1, 2*node_idx, mt_addr)
        right = FORS_TreeHash(pp, secret_seed, public_seed, tree_idx, height-1, 2*node_idx+1, mt_addr)
        parent = left + right
        #print(len(parent), parent.hex())
        
    addr = FORS_Addr_TreeHash(height, leaf_idx, mt_addr)
    #print(len(addr), addr.hex())
    node = THash(pp, public_seed, addr, parent)
    #print(len(node), node.hex())
    return node

def FORS_GeneratePublicKey(pp, secret_seed, public_seed=None, mt_addr=[0, 0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    k = pp[3]; a = pp[4]
    
    if public_seed == None:
        public_seed = random.randbytes(n)
    nodes = list()
    for i in range(0, k):
        node = FORS_TreeHash(pp, secret_seed, public_seed, i, a, 0, mt_addr)
        nodes.append(node)
    addr = FORS_Addr_PublicKey(mt_addr)
    public_root = THash(pp, public_seed, addr, b"".join(nodes))
    return (public_seed, public_root)


def FORS_Sign(pp, secret_seed, pk, msg, rand=None, mt_addr=[0, 0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    k = pp[3]; a = pp[4]
    (public_seed, public_root) = pk
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(secret_seed) == bytes and len(secret_seed) == n
    #assert type(msg) == bytes

    if rand == None:
        rand = random.randbytes(n)
    #assert type(rand) == bytes and len(rand) == n
    values = FORS_PreprocessMessage(pp, pk, rand, msg)
    #assert len(values) == k
    #print(values)
    
    sigs = list()
    for i in range(0, k):
        v = values[i]
        leaf_idx = i*(2**a) + v
        addr = FORS_Addr_SecretKey(leaf_idx, mt_addr)
        #print(len(addr), addr.hex())
        sig = PRF(pp, secret_seed, public_seed, addr)
        #print(len(sig), sig.hex())
        auth = list()
        for j in range(0, a):
            if v%2 == 0:
                node = FORS_TreeHash(pp, secret_seed, public_seed, i, j, v+1, mt_addr)
            else:
                node = FORS_TreeHash(pp, secret_seed, public_seed, i, j, v-1, mt_addr)
            auth.append(node)
            v >>= 1
        sigs.append((sig, auth))
    return (rand, sigs)
    
def FORS_Verify(pp, pk, signature, msg, mt_addr=[0, 0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    k = pp[3]; a = pp[4]
    (public_seed, public_root) = pk
    (rand, sigs) = signature
    #assert len(signature) == k
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(msg) == bytes
    #assert type(rand) == bytes and len(rand) == n
    
    values = FORS_PreprocessMessage(pp, pk, rand, msg)
    #assert len(values) == k
    #print(values)
    
    nodes = list()
    for i in range(0, k):
        (sig, auth) = sigs[i]
        #assert type(sig) == bytes and len(sig) == n
        #assert len(auth) == a
        v = values[i]
        leaf_idx = i*(2**a) + v
        addr = FORS_Addr_TreeHash(0, leaf_idx, mt_addr)
        #print(len(addr), addr.hex())
        node = THash(pp, public_seed, addr, sig)
        #print(len(node), node.hex())
        for j in range(1, a+1):
            if v%2 == 0:
                parent = node + auth[j-1]
            else:
                parent = auth[j-1] + node
            v >>= 1
            leaf_idx = i*(2**(a-j)) + v
            addr = FORS_Addr_TreeHash(j, leaf_idx, mt_addr)
            #print(len(addr), addr.hex())
            node = THash(pp, public_seed, addr, parent)
            #print(len(node), node.hex())
        #assert v == 0
        nodes.append(node)
    addr = FORS_Addr_PublicKey(mt_addr)
    public_root1 = THash(pp, public_seed, addr, b"".join(nodes))
    print(len(public_root1), public_root1.hex())
    return public_root == public_root1
