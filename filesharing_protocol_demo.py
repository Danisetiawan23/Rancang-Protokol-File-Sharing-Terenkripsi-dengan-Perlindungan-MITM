"""
Checkpoint 3 - Demo MITM sebelum dan sesudah, berbasis class (Alice, Bob, Server, Eve).

"""

import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature, InvalidTag


# ==========================================================
# FUNGSI BANTU
# ==========================================================

def raw(pub):
    return pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )


def enc(*parts):
    return b"".join(
        len(p).to_bytes(4, "big") + p for p in parts
    )


def kdf(secret, salt, info):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    ).derive(secret)


def x25519_pub(data):
    return x25519.X25519PublicKey.from_public_bytes(data)


def garis():
    print("=" * 65)


def judul(teks):
    garis()
    print(teks.center(65))
    garis()


def jeda():
    input("\nTekan ENTER untuk kembali ke menu...")


# ==========================================================
# CLASS BOB
# ==========================================================

class Bob:
    def __init__(self):
        self.ik = ed25519.Ed25519PrivateKey.generate()
        self.dh = x25519.X25519PrivateKey.generate()
        self.seen = set()

    def ik_pub(self):
        return self.ik.public_key()

    def publish_bundle(self):
        bundle = enc(
            b"v1",
            b"Bob",
            raw(self.dh.public_key())
        )
        return bundle, self.ik.sign(bundle)

    def receive(self, pkg, alice_ik_pub):
        p = enc(
            pkg["aad"],
            pkg["EK"],
            pkg["n1"],
            pkg["ct"],
            pkg["n2"],
            pkg["wrapped"],
            hashlib.sha256(pkg["ct"]).digest()
        )

        alice_ik_pub.verify(pkg["sig"], p)

        assert pkg["aad"] not in self.seen, "Replay terdeteksi"

        ss = self.dh.exchange(x25519_pub(pkg["EK"]))

        kek = kdf(
            ss,
            pkg["EK"] + raw(self.dh.public_key()),
            b"fileshare-v1/kek"
        )

        fk = AESGCM(kek).decrypt(
            pkg["n2"],
            pkg["wrapped"],
            pkg["aad"]
        )

        data = AESGCM(fk).decrypt(
            pkg["n1"],
            pkg["ct"],
            pkg["aad"]
        )

        self.seen.add(pkg["aad"])

        return data


# ==========================================================
# CLASS ALICE
# ==========================================================

class Alice:
    def __init__(self, bob_ik_pub_trusted):
        self.ik = ed25519.Ed25519PrivateKey.generate()
        self.bob_ik_pub = bob_ik_pub_trusted

    def ik_pub(self):
        return self.ik.public_key()

    def send(self, bundle, sig_B, data, file_id=b"f001", version=1):

        self.bob_ik_pub.verify(sig_B, bundle)

        dh_b_pub = bundle[-32:]

        fk = os.urandom(32)
        ek = x25519.X25519PrivateKey.generate()

        ss = ek.exchange(x25519_pub(dh_b_pub))

        kek = kdf(
            ss,
            raw(ek.public_key()) + dh_b_pub,
            b"fileshare-v1/kek"
        )

        aad = enc(
            b"v1",
            file_id,
            b"Alice",
            b"Bob",
            version.to_bytes(4, "big")
        )

        n1 = os.urandom(12)
        n2 = os.urandom(12)

        ct = AESGCM(fk).encrypt(n1, data, aad)
        wrapped = AESGCM(kek).encrypt(n2, fk, aad)

        pkg = enc(
            aad,
            raw(ek.public_key()),
            n1,
            ct,
            n2,
            wrapped,
            hashlib.sha256(ct).digest()
        )

        return {
            "aad": aad,
            "EK": raw(ek.public_key()),
            "n1": n1,
            "ct": ct,
            "n2": n2,
            "wrapped": wrapped,
            "sig": self.ik.sign(pkg)
        }


# ==========================================================
# CLASS SERVER
# ==========================================================

class Server:
    def __init__(self):
        self.storage = {}


# ==========================================================
# CLASS EVE
# ==========================================================

class Eve:
    def __init__(self):
        self.dh = x25519.X25519PrivateKey.generate()
        self.ik = ed25519.Ed25519PrivateKey.generate()

    def fake_bundle(self):
        bundle = enc(
            b"v1",
            b"Bob",
            raw(self.dh.public_key())
        )

        return bundle, self.ik.sign(bundle)


# ==========================================================
# FUNGSI PENGUJIAN
# ==========================================================

def cek(nama, fungsi):
    try:
        fungsi()
        print(f"  [!] {nama}: LOLOS (desain gagal)")
    except (InvalidSignature, InvalidTag, AssertionError) as e:
        print(f"  [OK] {nama}: DITOLAK ({type(e).__name__})")


# ==========================================================
# PERSIAPAN SIMULASI
# ==========================================================

def persiapan():
    bob = Bob()
    alice = Alice(bob.ik_pub())
    eve = Eve()

    data = b"Rahasia: nilai ujian.pdf"

    bundle, sig_B = bob.publish_bundle()
    pkg = alice.send(bundle, sig_B, data)

    return bob, alice, eve, data, bundle, sig_B, pkg


# ==========================================================
# MENU 1 - MITM TANPA AUTENTIKASI
# ==========================================================

def demo_mitm():
    judul("DEMO 1 - MITM TANPA AUTENTIKASI")

    bob = Bob()
    eve = Eve()

    data = b"Rahasia: nilai ujian.pdf"

    print("\n[1] Alice mengambil kunci publik dari pihak yang tidak diverifikasi.")

    ek = x25519.X25519PrivateKey.generate()

    ss_alice = ek.exchange(eve.dh.public_key())
    k_alice = kdf(ss_alice, b"", b"naif")

    ct = AESGCM(k_alice).encrypt(
        b"\0" * 12,
        data,
        b""
    )

    print("[2] Eve menerima komunikasi dan memiliki kunci yang sesuai.")

    ss_eve = eve.dh.exchange(ek.public_key())
    k_eve = kdf(ss_eve, b"", b"naif")

    hasil = AESGCM(k_eve).decrypt(
        b"\0" * 12,
        ct,
        b""
    )

    print("\nHASIL SIMULASI:")
    print("Status serangan : BERHASIL")
    print("Pesan terbaca   :", hasil.decode())

    print("\nKesimpulan:")
    print("DH tanpa autentikasi tidak dapat memastikan identitas")
    print("pihak yang sedang berkomunikasi.")


# ==========================================================
# MENU 2 - PROTOKOL AMAN
# ==========================================================

def demo_aman():
    judul("DEMO 2 - PROTOKOL DENGAN AUTENTIKASI")

    bob, alice, eve, data, bundle, sig_B, pkg = persiapan()

    print("\n[1] Alice memverifikasi tanda tangan digital Bob.")
    print("[2] Alice mengenkripsi file menggunakan AES-GCM.")
    print("[3] Bob menerima paket dan memverifikasi tanda tangan Alice.")

    hasil = bob.receive(pkg, alice.ik_pub())

    print("\nHASIL SIMULASI:")
    print("Status          : BERHASIL")
    print("Pengirim        : Alice")
    print("Penerima        : Bob")
    print("Pesan diterima  :", hasil.decode())

    print("\nKesimpulan:")
    print("Autentikasi identitas membantu mencegah MITM.")


# ==========================================================
# MENU 3 - PENGUJIAN MITM
# ==========================================================

def uji_mitm():
    judul("PENGUJIAN SERANGAN MITM")

    bob, alice, eve, data, bundle, sig_B, pkg = persiapan()

    fake_bundle, fake_sig = eve.fake_bundle()

    print("\nPengujian 1: Prekey Bob diganti Eve.")

    cek(
        "Prekey palsu dengan tanda tangan Bob",
        lambda: alice.send(fake_bundle, sig_B, data)
    )

    print("\nPengujian 2: Prekey dan tanda tangan Eve.")

    cek(
        "Prekey palsu dengan tanda tangan Eve",
        lambda: alice.send(fake_bundle, fake_sig, data)
    )


# ==========================================================
# MENU 4 - MANIPULASI CIPHERTEXT
# ==========================================================

def uji_ciphertext():
    judul("PENGUJIAN MANIPULASI CIPHERTEXT")

    bob, alice, eve, data, bundle, sig_B, pkg = persiapan()

    bad = dict(pkg)

    bad["ct"] = (
        pkg["ct"][:-1] +
        bytes([pkg["ct"][-1] ^ 1])
    )

    def baru():
        b = Bob()
        b.dh = bob.dh
        b.ik = bob.ik
        return b

    cek(
        "Ciphertext dimanipulasi",
        lambda: baru().receive(bad, alice.ik_pub())
    )


# ==========================================================
# MENU 5 - PEMALSUAN IDENTITAS
# ==========================================================

def uji_pemalsuan():
    judul("PENGUJIAN PEMALSUAN IDENTITAS")

    bob, alice, eve, data, bundle, sig_B, pkg = persiapan()

    eve_sign = dict(pkg)

    eve_sign["sig"] = eve.ik.sign(
        b"paket buatan eve"
    )

    def baru():
        b = Bob()
        b.dh = bob.dh
        b.ik = bob.ik
        return b

    cek(
        "Paket dengan tanda tangan Eve",
        lambda: baru().receive(eve_sign, alice.ik_pub())
    )


# ==========================================================
# MENU 6 - SERANGAN REPLAY
# ==========================================================

def uji_replay():
    judul("PENGUJIAN SERANGAN REPLAY")

    bob, alice, eve, data, bundle, sig_B, pkg = persiapan()

    print("\nPengiriman pertama:")
    hasil = bob.receive(pkg, alice.ik_pub())
    print("  [OK] Pesan diterima:", hasil.decode())

    print("\nPengiriman kedua (paket yang sama):")

    cek(
        "Paket lama dikirim ulang",
        lambda: bob.receive(pkg, alice.ik_pub())
    )


# ==========================================================
# MENU 7 - JALANKAN SEMUA
# ==========================================================

def semua_pengujian():
    demo_mitm()
    jeda()

    demo_aman()
    jeda()

    uji_mitm()
    jeda()

    uji_ciphertext()
    jeda()

    uji_pemalsuan()
    jeda()

    uji_replay()


# ==========================================================
# MENU UTAMA
# ==========================================================

def menu():
    while True:

        os.system("cls" if os.name == "nt" else "clear")

        print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║             SIMULASI KEAMANAN FILE SHARING                    ║
║                                                               ║
║          MAN IN THE MIDDLE ATTACK (MITM)                      ║
║                                                               ║
║                  CHECKPOINT 3                                 ║
║                                                               ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  [1] Demo MITM Tanpa Autentikasi                              ║
║  [2] Demo Protokol Aman                                       ║
║  [3] Pengujian Serangan MITM                                  ║
║  [4] Pengujian Manipulasi Ciphertext                          ║
║  [5] Pengujian Pemalsuan Identitas                            ║
║  [6] Pengujian Serangan Replay                                ║
║  [7] Jalankan Semua Pengujian                                 ║
║  [8] Keluar                                                   ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
""")

        pilihan = input("Pilih menu [1-8]: ").strip()

        if pilihan == "1":
            demo_mitm()
            jeda()

        elif pilihan == "2":
            demo_aman()
            jeda()

        elif pilihan == "3":
            uji_mitm()
            jeda()

        elif pilihan == "4":
            uji_ciphertext()
            jeda()

        elif pilihan == "5":
            uji_pemalsuan()
            jeda()

        elif pilihan == "6":
            uji_replay()
            jeda()

        elif pilihan == "7":
            semua_pengujian()
            jeda()

        elif pilihan == "8":
            print("\nTerima kasih telah menggunakan program.")
            print("Program selesai.\n")
            break

        else:
            print("\nPilihan tidak valid! Silakan pilih 1-8.")
            jeda()


# ==========================================================
# PROGRAM UTAMA
# ==========================================================

if __name__ == "__main__":
    menu()
