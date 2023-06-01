# PySig
signature shemes in python

* pure python without any external dependencies
* just copy and paste; no license
* simple implementation for understanding not for performance

### SPHINCS+

* Specification: https://sphincs.org/data/sphincs+-r3.1-specification.pdf
* Reference Implementation: https://github.com/sphincs/sphincsplus
* Section 6. SPHINCS+
* If you have found a pair of input and output which is not equal to that of the reference implementaion, please let me know.

```python

n = 16
algo = "shake"
robust = True
k = 14; a = 12
w = 4; h = 9; d = 7
pp = (n, algo, robust, k, a, w, h, d)

assert w in [4, 8]
    
secret_seed = b"\xaa"*n
public_seed = b"\xcc"*n

public_root = SPHINCS_GeneratePulicKey(pp, secret_seed, public_seed)
print(len(public_root), public_root.hex())

#16 9ab7a7b30bc9c6a8637a54caef3f9c27

rand = bytes.fromhex("a2fac94d6e320ad83fc049c6ba21033b")
msg = b"\xff"*32

signature = SPHINCS_Sign(pp, secret_seed, public_seed, public_root, msg, rand)

#        Random:                                           16 a2fac94d6e320ad83fc049c6ba21033b
#Hashed Message:         6391030117691388          241     21 265dc48ab5c151e14d73ddc62ab3646a5e1474ca73
#          FORS:                                           16 2f4db3d8172f2680e71f13e8b6dd3645
#       XMSS-MT:               tree_index   leaf_index
#    0-th layer:         6391030117691388          241 =>  16 85a91c6b80a1849f411d02ff73c1262a
#    1-th layer:           12482480698615          508 =>  16 774a93c53745b203bc89c2ccedcc40bf
#    2-th layer:              24379845114          247 =>  16 e698d35c86bc973a046f0cdbfed79bc1
#    3-th layer:                 47616884          506 =>  16 286c22499dca6d3a8cf0ba9ed9a8b5ed
#    4-th layer:                    93001          372 =>  16 ae3287acf595e9ef928f73484a60058e
#    5-th layer:                      181          329 =>  16 81b4e5c89d697835b45d23843b1f4e95
#    6-th layer:                        0          181 =>  16 9ab7a7b30bc9c6a8637a54caef3f9c27

root = SPHINCS_Verify(pp, public_seed, public_root, signature, msg)
assert root == public_root
```


#### FORS

* Section 5. FORS: Forest Of Random Subsets

```python
n = 16
algo = "shake"
robust = True
k = 14; a = 12

pp = (n, algo, robust, k, a)

secret_seed = b"\xaa"*n
#public_seed = b"\xbb"*n
public_seed = None

mt_addr = [0, 0, 0]

pk = FORS_GeneratePublicKey(pp, secret_seed, public_seed, mt_addr)
(public_seed, public_root) = pk

msg = b"Hello World!"

#rand = random.randbytes(n)
rand = None

signature = FORS_Sign(pp, sk, pk, msg, rand, mt_addr)
(rand, sigs) = signature

assert FORS_Verify(pp, pk, signature, msg, mt_addr)
```

#### WOTS+

* Section 3. WOTS+ One-Time Signatures

```python
n = 16
algo = "shake"
robust = True
w = 4
pp = (n, algo, robust, w)

secret_seed = b"\xaa"*n
#public_seed = b"\xbb"*n
public_seed = None

mt_addr = [0, 0, 0]
pk = WOTS_GeneratePublicKey(pp, secret_seed, public_seed, mt_addr)
(public_seed, public_root) = pk

msg = b"Hello World!"

#rand = random.randbytes(n)
rand = None

signature = WOTS_Sign(pp, sk, pk, msg, rand, mt_addr)
(rand, sigs) = signature

assert WOTS_Verify(pp, pk, signature, msg, mt_addr)
```

#### XMSS

* Section 4.1. (Fixed Input-Length) XMSS

#### HT(XMSS-MT)

* Section 4.2. HT: The Hypertee
