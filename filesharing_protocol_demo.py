"""
Checkpoint 3 - Demo MITM sebelum dan sesudah, berbasis class (Alice, Bob, Server, Eve).

"""
import os, hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature, InvalidTag

# ---------- fungsi bantu ----------
def raw(pub): return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def enc(*parts): return b"".join(len(p).to_bytes(4, "big") + p for p in parts)  # canonical_encode
def kdf(secret, salt, info): return HKDF(hashes.SHA256(), 32, salt, info).derive(secret)
def x25519_pub(b): return x25519.X25519PublicKey.from_public_bytes(b)

# ---------- aktor ----------
class Bob:
    def __init__(self):
        self.ik = ed25519.Ed25519PrivateKey.generate()      # identitas (Ed25519)
        self.dh = x25519.X25519PrivateKey.generate()        # prekey (X25519)
        self.seen = set()
    def ik_pub(self): return self.ik.public_key()
    def publish_bundle(self):
        bundle = enc(b"v1", b"Bob", raw(self.dh.public_key()))
        return bundle, self.ik.sign(bundle)                 # bundle + sig_B
    def receive(self, pkg, alice_ik_pub):
        p = enc(pkg["aad"], pkg["EK"], pkg["n1"], pkg["ct"], pkg["n2"], pkg["wrapped"],
                hashlib.sha256(pkg["ct"]).digest())         # hitung ulang dari data diterima
        alice_ik_pub.verify(pkg["sig"], p)                  # verifikasi sig_A
        assert pkg["aad"] not in self.seen, "replay terdeteksi"
        ss = self.dh.exchange(x25519_pub(pkg["EK"]))
        kek = kdf(ss, pkg["EK"] + raw(self.dh.public_key()), b"fileshare-v1/kek")
        fk = AESGCM(kek).decrypt(pkg["n2"], pkg["wrapped"], pkg["aad"])
        data = AESGCM(fk).decrypt(pkg["n1"], pkg["ct"], pkg["aad"])
        self.seen.add(pkg["aad"]); return data

class Alice:
    def __init__(self, bob_ik_pub_trusted):
        self.ik = ed25519.Ed25519PrivateKey.generate()
        self.bob_ik_pub = bob_ik_pub_trusted                # hasil cek fingerprint
    def ik_pub(self): return self.ik.public_key()
    def send(self, bundle, sig_B, data, file_id=b"f001", version=1):
        self.bob_ik_pub.verify(sig_B, bundle)               # tolak jika prekey bukan dari Bob
        dh_b_pub = bundle[-32:]
        fk = os.urandom(32); ek = x25519.X25519PrivateKey.generate()
        ss = ek.exchange(x25519_pub(dh_b_pub))
        kek = kdf(ss, raw(ek.public_key()) + dh_b_pub, b"fileshare-v1/kek")
        aad = enc(b"v1", file_id, b"Alice", b"Bob", version.to_bytes(4, "big"))
        n1, n2 = os.urandom(12), os.urandom(12)
        ct = AESGCM(fk).encrypt(n1, data, aad); wrapped = AESGCM(kek).encrypt(n2, fk, aad)
        pkg = enc(aad, raw(ek.public_key()), n1, ct, n2, wrapped, hashlib.sha256(ct).digest())
        return dict(aad=aad, EK=raw(ek.public_key()), n1=n1, ct=ct, n2=n2, wrapped=wrapped,
                    sig=self.ik.sign(pkg))

class Server:                                               # tidak dipercaya
    def __init__(self): self.storage = {}

class Eve:                                                  # penyerang aktif / server jahat
    def __init__(self):
        self.dh = x25519.X25519PrivateKey.generate()
        self.ik = ed25519.Ed25519PrivateKey.generate()
    def fake_bundle(self):
        b = enc(b"v1", b"Bob", raw(self.dh.public_key()))
        return b, self.ik.sign(b)                           # ditandatangani kunci Eve sendiri

def cek(nama, f):
    try: f(); print(f"  [!] {nama}: LOLOS (desain gagal)")
    except (InvalidSignature, InvalidTag, AssertionError) as e:
        print(f"  [OK] {nama}: ditolak ({type(e).__name__} {e})".replace(" )", ")"))

# =====================================================================
print("=== BAGIAN A. Tanpa autentikasi (DH polos): MITM BERHASIL ===")
bob = Bob(); eve = Eve(); data = b"Rahasia: nilai ujian.pdf"
# Alice mengambil kunci 'Bob' dari server tanpa verifikasi tanda tangan. Eve menggantinya.
dh_palsu = eve.dh.public_key()
ek = x25519.X25519PrivateKey.generate()
ss_alice = ek.exchange(dh_palsu)                            # Alice menyepakati kunci dengan EVE
k_alice = kdf(ss_alice, b"", b"naif")
ct = AESGCM(k_alice).encrypt(b"\0" * 12, data, b"")
ss_eve = eve.dh.exchange(ek.public_key())                   # Eve menurunkan kunci yang sama
k_eve = kdf(ss_eve, b"", b"naif")
print("  Eve membaca berkas:", AESGCM(k_eve).decrypt(b"\0" * 12, ct, b"").decode())
print("  -> DH tidak mengautentikasi lawan bicara (seperti Praktikum 5C).\n")

print("=== BAGIAN B. Protokol dengan tanda tangan identitas: MITM GAGAL ===")
bob = Bob(); alice = Alice(bob.ik_pub()); eve = Eve()
bundle, sig_B = bob.publish_bundle()
pkg = alice.send(bundle, sig_B, data)
print("  Normal       :", bob.receive(pkg, alice.ik_pub()).decode())
fb, fs = eve.fake_bundle()
cek("Prekey Bob diganti Eve (sig_B asli)", lambda: alice.send(fb, sig_B, data))
cek("Prekey diganti + tanda tangan Eve  ", lambda: alice.send(fb, fs, data))
def baru(): b = Bob(); b.dh = bob.dh; b.ik = bob.ik; return b   # Bob baru, memori replay kosong
bad = dict(pkg); bad["ct"] = pkg["ct"][:-1] + bytes([pkg["ct"][-1] ^ 1])
cek("Ciphertext diubah                  ", lambda: baru().receive(bad, alice.ik_pub()))
eve_sign = dict(pkg); eve_sign["sig"] = eve.ik.sign(b"paket buatan eve")
cek("Pengirim dipalsukan (ttd Eve)      ", lambda: baru().receive(eve_sign, alice.ik_pub()))
cek("Paket lama dikirim ulang (replay)  ", lambda: bob.receive(pkg, alice.ik_pub()))
