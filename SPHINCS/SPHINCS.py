import hashlib, random

def XOR(x, y):
    #assert len(x) == len(y)
    n = len(x)
    z = list(x[i]^y[i] for i in range(0, n))
    return bytes(z)

#################################################################################################

supported_hash_algorithms = [
    "shake",
    #"sha2",
    #"haraka",
]

## pp = [n, algo, robust, k, a, w, h, d]

# SK Generation
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
def Randomize(pp, secret_seed, optional_rand, msg):
    n = pp[0]; algo = pp[1]
    #assert type(secret_seed) == bytes and len(secret_seed) == n
    #assert type(optional_rand) == bytes and len(optional_rand) == n
    #assert type(msg) == bytes
    if algo == "shake":
        rand = hashlib.new("shake256", secret_seed+optional_rand+msg).digest(n)
    else:
        assert False
    return rand

# Message Digest
def MHash(pp, pk, rand, msg):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    k = pp[3]; a = pp[4]
    w = pp[5]; h = pp[6]; d = pp[7]
    #assert type(pk) == bytes and len(pk) == 2*n
    #assert type(rand) == bytes and len(rand) == n
    #assert type(msg) == bytes
    l0 = (k*a+7)//8  ## FORS Message Size
    l1 = (h*(d-1)+7)//8
    l2 = (h+7)//8
    l = l0 + l1 + l2
    #print(l0, l1, l2)
    if algo == "shake":
        temp = hashlib.new("shake256", rand+pk+msg).digest(l)
        i = 0
        digest = temp[i:i+l0]; i += l0
        mt_tree_idx = int.from_bytes(temp[i:i+l1], "big", signed=False) & ((1<<(h*(d-1))) - 1); i += l1
        mt_leaf_idx = int.from_bytes(temp[i:i+l2], "big", signed=False) & ((1<<h) - 1)
    else:
        assert False
    return (digest, mt_tree_idx, mt_leaf_idx)


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
 
#################################################################################################

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
  
#################################################################################################

def FORS_Addr_TreeHash(height, leaf_idx, mt_addr=[0, 0, 0]):
    (mt_layer, mt_tree_idx, mt_leaf_idx) = mt_addr
    return MakeAddress([mt_layer, mt_tree_idx, 3, mt_leaf_idx, height, leaf_idx])

def FORS_Addr_PublicKey(mt_addr=[0, 0, 0]):
    (mt_layer, mt_tree_idx, mt_leaf_idx) = mt_addr
    return MakeAddress([mt_layer, mt_tree_idx, 4, mt_leaf_idx, 0, 0])

def FORS_Addr_SecretKey(leaf_idx, mt_addr=[0, 0, 0]):
    (mt_layer, mt_tree_idx, mt_leaf_idx) = mt_addr
    return MakeAddress([mt_layer, mt_tree_idx, 6, mt_leaf_idx, 0, leaf_idx])

#################################################################################################

def FORS_Preprocess(pp, hashed_msg):
    n = pp[0]; #algo = pp[1]; robust = pp[2]
    k = pp[3]; a = pp[4]
    #assert type(hashed_msg) == bytes and len(hashed_msg) >= (k*a+7)//8
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

def FORS_GeneratePublicKey(pp, secret_seed, public_seed, mt_addr=[0, 0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    k = pp[3]; a = pp[4]
    
    nodes = list()
    for i in range(0, k):
        node = FORS_TreeHash(pp, secret_seed, public_seed, i, a, 0, mt_addr)
        nodes.append(node)
    addr = FORS_Addr_PublicKey(mt_addr)
    pk = THash(pp, public_seed, addr, b"".join(nodes))
    return pk


def FORS_Sign(pp, secret_seed, public_seed, hashed_msg, mt_addr=[0, 0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    k = pp[3]; a = pp[4]
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(secret_seed) == bytes and len(secret_seed) == n
    #assert type(hashed_msg) == bytes

    values = FORS_Preprocess(pp, hashed_msg)
    #assert len(values) == k
    #print(values)
    
    signature = list()
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
        signature.append((sig, auth))
    return signature
    
def FORS_Verify(pp, public_seed, signature, hashed_msg, mt_addr=[0, 0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    k = pp[3]; a = pp[4]
    #assert len(signature) == k
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(hashed_msg) == bytes
    
    values = FORS_Preprocess(pp, hashed_msg)
    #assert len(values) == k
    #print(values)
    
    nodes = list()
    for i in range(0, k):
        (sig, auth) = signature[i]
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
    pk = THash(pp, public_seed, addr, b"".join(nodes))
    return pk

#################################################################################################

def WOTS_Addr_ChainHash(chain_idx, hash_idx, mt_addr=[0, 0, 0]):
    (mt_layer, mt_tree_idx, mt_leaf_idx) = mt_addr
    return MakeAddress([mt_layer, mt_tree_idx, 0, mt_leaf_idx, chain_idx, hash_idx])

def WOTS_Addr_PublicKey(mt_addr=[0, 0, 0]):
    (mt_layer, mt_tree_idx, mt_leaf_idx) = mt_addr
    return MakeAddress([mt_layer, mt_tree_idx, 1, mt_leaf_idx, 0, 0])

def WOTS_Addr_SecretKey(chain_idx, mt_addr=[0, 0, 0]):
    (mt_layer, mt_tree_idx, mt_leaf_idx) = mt_addr
    return MakeAddress([mt_layer, mt_tree_idx, 5, mt_leaf_idx, chain_idx, 0])

#n = 16, 24, 32
#w = 4, 8

def WOTS_Preprocess(pp, hashed_msg):
    n = pp[0]; #algo = pp[1]; robust = pp[2]
    #k = pp[3]; a = pp[4]
    w = pp[5]; #h = pp[6]; d = pp[7]
    
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


def WOTS_GeneratePulicKey(pp, secret_seed, public_seed, mt_addr=[0, 0, 0]):
    n = pp[0]; #algo = pp[1]; robust = pp[2]
    #k = pp[3]; a = pp[4]
    w = pp[5]; #h = pp[6]; d = pp[7]

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
    node = THash(pp, public_seed, addr, b"".join(nodes))
    #print(len(addr), addr.hex())
    #print(len(node), node.hex())
    return node

def WOTS_Sign(pp, secret_seed, public_seed, hashed_msg, mt_addr=[0, 0, 0]):
    n = pp[0]; #algo = pp[1]; robust = pp[2]
    #k = pp[3]; a = pp[4]
    w = pp[5]; #h = pp[6]; d = pp[7]

    assert type(secret_seed) == bytes and len(secret_seed) == n
    assert type(public_seed) == bytes and len(public_seed) == n
    
    values = WOTS_Preprocess(pp, hashed_msg)
    l1 = n*(8//w)
    l = len(values)
    l2 = l - l1
    #print(n, w, l1, l2, l)
    
    nodes = list()
    for i in range(0, l):
        #print("-"*100)
        addr = WOTS_Addr_SecretKey(i, mt_addr)
        node = PRF(pp, secret_seed, public_seed, addr)
        #print(len(addr), addr.hex())
        #print(len(node), node.hex())

        for j in range(0, values[i]):
            addr = WOTS_Addr_ChainHash(i, j, mt_addr)
            node = THash(pp, public_seed, addr, node)
        nodes.append(node)
        #print(len(addr), addr.hex())
        #print(len(node), node.hex())
    return nodes

def WOTS_Verify(pp, public_seed, signature, hashed_msg, mt_addr=[0, 0, 0]):
    n = pp[0]; #algo = pp[1]; robust = pp[2]
    #k = pp[3]; a = pp[4]
    w = pp[5]; #h = pp[6]; d = pp[7]

    assert type(public_seed) == bytes and len(public_seed) == n
    
    values = WOTS_Preprocess(pp, hashed_msg)
    assert len(values) == len(signature)
    l1 = n*(8//w)
    l = len(values)
    l2 = l - l1
    #print(n, w, l1, l2, l)
    
    nodes = list()
    for i in range(0, l):
        #print("-"*100)
        node = signature[i]
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
    node = THash(pp, public_seed, addr, b"".join(nodes))
    #print(len(addr), addr.hex())
    #print(len(node), node.hex())
    return node
  
#################################################################################################

def XMSS_Addr_TreeHash(height, node_idx, tree_addr=[0, 0]):
    (mt_layer, mt_tree_idx) = tree_addr
    return MakeAddress([mt_layer, mt_tree_idx, 2, 0, height, node_idx])

def XMSS_TreeHash(pp, secret_seed, public_seed, height, node_idx, tree_addr=[0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    #k = pp[3]; a = pp[4];
    #w = pp[5]; 
    h = pp[6]; #d = pp[7]
    (mt_layer, mt_tree_idx) = tree_addr
    
    assert height >= 0 and height <= h
    assert node_idx >= 0 and node_idx < 2**(h-height)
    
    if height == 0:
        mt_addr = [mt_layer, mt_tree_idx, node_idx]
        node = WOTS_GeneratePulicKey(pp, secret_seed, public_seed, mt_addr)
        #print(len(node), node.hex())
    else:
        left = XMSS_TreeHash(pp, secret_seed, public_seed, height-1, 2*node_idx, tree_addr)
        right = XMSS_TreeHash(pp, secret_seed, public_seed, height-1, 2*node_idx+1, tree_addr)
        addr = XMSS_Addr_TreeHash(height, node_idx, tree_addr)
        #print(len(addr), addr.hex())
        node = THash(pp, public_seed, addr, left+right)
        #print(len(node), node.hex())
    return node

def XMSS_GeneratePulicKey(pp, secret_seed, public_seed, tree_addr=[0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    #k = pp[3]; a = pp[4];
    #w = pp[5]; 
    h = pp[6]; #d = pp[7]

    height = h
    node_idx = 0
    node = XMSS_TreeHash(pp, secret_seed, public_seed, height, node_idx, tree_addr)
    #print(len(node), node.hex())
    return node

def XMSS_Sign(pp, secret_seed, public_seed, hashed_msg, leaf_idx, tree_addr=[0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    #k = pp[3]; a = pp[4];
    #w = pp[5]; 
    h = pp[6]; #d = pp[7]
    (mt_layer, mt_tree_idx) = tree_addr
    
    assert leaf_idx >= 0 and leaf_idx < 2**h
    mt_addr = [mt_layer, mt_tree_idx, leaf_idx]
    sigs = WOTS_Sign(pp, secret_seed, public_seed, hashed_msg, mt_addr)
    
    auth = list()
    node_idx = leaf_idx
    for i in range(0, h):
        if node_idx%2 == 0:
            node = XMSS_TreeHash(pp, secret_seed, public_seed, i, node_idx+1, tree_addr)        
        else:
            node = XMSS_TreeHash(pp, secret_seed, public_seed, i, node_idx-1, tree_addr)
        node_idx >>= 1
        auth.append(node)
    signature = (sigs, auth)
    return signature

def XMSS_Verify(pp, public_seed, signature, hashed_msg, leaf_idx, tree_addr=[0, 0]):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    #k = pp[3]; a = pp[4];
    #w = pp[5]; 
    h = pp[6]; #d = pp[7]
    (sigs, auth) = signature
    (mt_layer, mt_tree_idx) = tree_addr

    assert leaf_idx >= 0 and leaf_idx < 2**h
    mt_addr = [mt_layer, mt_tree_idx, leaf_idx]
    node = WOTS_Verify(pp, public_seed, sigs, hashed_msg, mt_addr)
    node_idx = leaf_idx
    for i in range(0, h):
        addr = XMSS_Addr_TreeHash(i+1, node_idx>>1, tree_addr)
        if node_idx%2 == 0:
            node = THash(pp, public_seed, addr, node+auth[i])
        else:
            node = THash(pp, public_seed, addr, auth[i]+node)    
        node_idx >>= 1
    return node
  
#################################################################################################
  
def XMSS_MT_GeneratePulicKey(pp, secret_seed, public_seed):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    #k = pp[3]; a = pp[4];
    #w = pp[5]; 
    h = pp[6]; d = pp[7]
    
    mt_layer = d-1
    mt_tree_idx = 0
    tree_addr = (mt_layer, mt_tree_idx)
    node = XMSS_GeneratePulicKey(pp, secret_seed, public_seed, tree_addr)
    #print(len(node), node.hex())
    return node

def XMSS_MT_Sign(pp, secret_seed, public_seed, hashed_msg, mt_tree_idx, leaf_idx):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    #k = pp[3]; a = pp[4];
    #w = pp[5]; 
    h = pp[6]; d = pp[7]
    
    #assert mt_tree_idx >= 0 and mt_tree_idx < 2**((d-1)*h)
    #assert leaf_idx >= 0 and leaf_idx < 2**h    
    
    signature = list()
    node = hashed_msg
    for i in range(0, d):
        tree_addr = (i, mt_tree_idx)
        sig = XMSS_Sign(pp, secret_seed, public_seed, node, leaf_idx, tree_addr)
        signature.append(sig)
        node = XMSS_Verify(pp, public_seed, sig, node, leaf_idx, tree_addr)
        print(f"{tree_addr[0]:5}-th layer: {tree_addr[1]:24} {leaf_idx:12} => ",  len(node), node.hex())
        leaf_idx = mt_tree_idx%(2**h)
        mt_tree_idx >>= h
    return signature

def XMSS_MT_Verify(pp, public_seed, signature, hashed_msg, mt_tree_idx, leaf_idx):
    n = pp[0]; algo = pp[1]; robust = pp[2]
    #k = pp[3]; a = pp[4];
    #w = pp[5]; 
    h = pp[6]; d = pp[7]
    
    #assert mt_tree_idx >= 0 and mt_tree_idx < 2**((d-1)*h)
    #assert leaf_idx >= 0 and leaf_idx < 2**h    
    node = hashed_msg
    for i in range(0, d):
        tree_addr = (i, mt_tree_idx)
        node = XMSS_Verify(pp, public_seed, signature[i], node, leaf_idx, tree_addr)
        print(f"{tree_addr[0]:5}-th layer: {tree_addr[1]:24} {leaf_idx:12} => ",  len(node), node.hex())
        leaf_idx = mt_tree_idx%(2**h)
        mt_tree_idx >>= h
    return node
  
#################################################################################################

def SPHINCS_GeneratePulicKey(pp, secret_seed, public_seed):
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(secret_seed) == bytes and len(secret_seed) == n
    return XMSS_MT_GeneratePulicKey(pp, secret_seed, public_seed)
    
def SPHINCS_Sign(pp, secret_seed, public_seed, public_root, msg, rand=None):
    n = pp[0]
    #assert type(secret_seed) == bytes and len(secret_seed) == n
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(public_root) == bytes and len(public_root) == n
    #assert type(msg) == bytes
    if rand == None:
        rand = random.randbytes(n)   
    assert type(rand) == bytes and len(rand) == n
    (hashed_msg, mt_tree_idx, leaf_idx) = MHash(pp, public_seed + public_root, rand, msg)
    print("        RANDOM:", " "*41, len(rand), rand.hex())
    print(f"Hashed Message: {mt_tree_idx:24} {leaf_idx:12}    ", len(hashed_msg), hashed_msg.hex())
    #assert type(hashed_msg) == bytes and len(hashed_msg) == n
    mt_addr = [0, mt_tree_idx, leaf_idx]
    fors_sig = FORS_Sign(pp, secret_seed, public_seed, hashed_msg, mt_addr)
    node = FORS_Verify(pp, public_seed, fors_sig, hashed_msg, mt_addr)
    print("          FORS:", " "*41, len(node), node.hex())
    xmss_mt_sig = XMSS_MT_Sign(pp, secret_seed, public_seed, node, mt_tree_idx, leaf_idx)
    return (rand, fors_sig, xmss_mt_sig)

def SPHINCS_Verify(pp, public_seed, public_root, signature, msg):
    n = pp[0]
    #assert type(public_seed) == bytes and len(public_seed) == n
    #assert type(public_root) == bytes and len(public_root) == n
    #assert type(msg) == bytes
    (rand, fors_sig, xmss_mt_sig) = signature
    assert type(rand) == bytes and len(rand) == n
    (hashed_msg, mt_tree_idx, leaf_idx) = MHash(pp, public_seed + public_root, rand, msg)
    print("        RANDOM:", " "*41, len(rand), rand.hex())
    print(f"Hashed Message: {mt_tree_idx:24} {leaf_idx:12}    ", len(hashed_msg), hashed_msg.hex())
    #assert type(hashed_msg) == bytes and len(hashed_msg) == n
    mt_addr = [0, mt_tree_idx, leaf_idx]
    node = FORS_Verify(pp, public_seed, fors_sig, hashed_msg, mt_addr)
    print("          FORS:", " "*41, len(node), node.hex())
    root = XMSS_MT_Verify(pp, public_seed, xmss_mt_sig, node, mt_tree_idx, leaf_idx)
    return root
