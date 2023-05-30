# PySig
signature shemes in python

* pure python without any external dependencies
* just copy and paste; no license
* simple implementation for PoC not for performance

### SPHINCS+

* https://sphincs.org/data/sphincs+-r3.1-specification.pdf
* Section 6. SPHINCS+

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
