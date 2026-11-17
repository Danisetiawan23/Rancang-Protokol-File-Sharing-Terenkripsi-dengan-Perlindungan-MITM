import os, hashlib, json
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature, InvalidTag

raw = lambda k: k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
enc = lambda *p: b"".join(len(x).to_bytes(4,"big")+x for x in p)   # canonical_encode
def hkdf(secret, salt, info): return HKDF(hashes.SHA256(),32,salt,info).derive(secret)

# setup
IK_A=ed25519.Ed25519PrivateKey.generate(); IK_B=ed25519.Ed25519PrivateKey.generate()
DH_B=x25519.X25519PrivateKey.generate()
bundle=enc(b"v1",b"Bob",raw(DH_B.public_key())); sig_bundle=IK_B.sign(bundle)

def send(IK_B_pub_trusted, bundle, sig_bundle, msg, file_id=b"f001", ver=1):
    IK_B_pub_trusted.verify(sig_bundle, bundle)
    DH_B_pub=x25519.X25519PublicKey.from_public_bytes(bundle[-32:])
    FK=os.urandom(32); EK=x25519.X25519PrivateKey.generate()
    ss=EK.exchange(DH_B_pub)
    KEK=hkdf(ss, raw(EK.public_key())+raw(DH_B_pub), b"fileshare-v1/kek")
    aad=enc(b"v1",file_id,b"Alice",b"Bob",ver.to_bytes(4,"big"))
    n1,n2=os.urandom(12),os.urandom(12)
    ct=AESGCM(FK).encrypt(n1,msg,aad); wrapped=AESGCM(KEK).encrypt(n2,FK,aad)
    pkg=enc(aad,raw(EK.public_key()),n1,ct,n2,wrapped,hashlib.sha256(ct).digest())
    return dict(aad=aad,EK=raw(EK.public_key()),n1=n1,ct=ct,n2=n2,wrapped=wrapped,pkg=pkg,sig=IK_A.sign(pkg))

def receive(p, seen=None):
    seen = set() if seen is None else seen
    pkg=enc(p["aad"],p["EK"],p["n1"],p["ct"],p["n2"],p["wrapped"],hashlib.sha256(p["ct"]).digest())  # dihitung ulang dari data diterima
    IK_A.public_key().verify(p["sig"], pkg)
    assert p["aad"] not in seen
    ss=DH_B.exchange(x25519.X25519PublicKey.from_public_bytes(p["EK"]))
    KEK=hkdf(ss,p["EK"]+raw(DH_B.public_key()),b"fileshare-v1/kek")
    FK=AESGCM(KEK).decrypt(p["n2"],p["wrapped"],p["aad"])
    m=AESGCM(FK).decrypt(p["n1"],p["ct"],p["aad"]); seen.add(p["aad"]); return m

msg=b"Laporan keuangan rahasia.pdf isi"
p=send(IK_B.public_key(),bundle,sig_bundle,msg)
print("1 normal        :", receive(p)==msg)
def expect(name,f):
    try: f(); print(name,": DITERIMA (GAGAL!)")
    except (InvalidSignature,InvalidTag,AssertionError) as e: print(name,": ditolak ->",type(e).__name__)
p2=dict(p); p2["ct"]=p["ct"][:-1]+bytes([p["ct"][-1]^1])
expect("2 ciphertext diubah ", lambda: receive(p2))
Eve=x25519.X25519PrivateKey.generate()
fake=enc(b"v1",b"Bob",raw(Eve.public_key()))
expect("3 prekey Bob diganti", lambda: send(IK_B.public_key(),fake,sig_bundle,msg))
Eve_sig=ed25519.Ed25519PrivateKey.generate().sign(fake)
expect("3b +tanda tangan Eve", lambda: send(IK_B.public_key(),fake,Eve_sig,msg))
S=set(); receive(p,S)
expect("4 replay            ", lambda: receive(p,S))
# 5 Eve fakes whole package signed w/ own key
EveIK=ed25519.Ed25519PrivateKey.generate(); p3=dict(p); p3["sig"]=EveIK.sign(p["pkg"])
expect("5 sender palsu      ", lambda: receive(p3,set()))
