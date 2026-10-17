"""The TPM proof checks, with a synthetic TPM and certificate chain (no hardware needed). The real chip is exercised by
thessley-passkey-linux/tests/integration_tpm.py (against thessley-pam-linux, which has the same code). Run from the repo root:
    python -m pytest tests/test_tpmproof.py
"""

import datetime
import hashlib
import hmac
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID, ObjectIdentifier

from thessley_pam_win import tpmproof as T


# ---- a pretend TPM ----------------------------------------------------------------------------------------------

def tpm2b(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b


def public_area(key: ec.EllipticCurvePrivateKey, attributes: int, scheme: bool = False) -> bytes:
    nums = key.public_key().public_numbers()
    sch = struct.pack(">HH", T.ALG_ECDSA, T.ALG_SHA256) if scheme else struct.pack(">H", T.ALG_NULL)
    return (struct.pack(">HHI", T.ALG_ECC, T.ALG_SHA256, attributes) + tpm2b(b"") + struct.pack(">H", T.ALG_NULL) + sch
            + struct.pack(">HH", T.CURVE_P256, T.ALG_NULL) + tpm2b(nums.x.to_bytes(32, "big")) + tpm2b(nums.y.to_bytes(32, "big")))


def spki(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def certify(ak_key, key_public: bytes, nonce: bytes, magic=T.MAGIC, typ=T.ST_CERTIFY, name=None, trailing=b"") -> tuple[bytes, bytes]:
    """The AK's TPMS_ATTEST over the key's name, and its TPMT_SIGNATURE."""
    attest = (struct.pack(">IH", magic, typ) + tpm2b(b"signer") + tpm2b(nonce) + b"\0" * (8 + 4 + 4 + 1 + 8)
              + tpm2b(name if name is not None else T.name(key_public)) + tpm2b(b"qualified") + trailing)
    r, s = utils.decode_dss_signature(ak_key.sign(attest, ec.ECDSA(hashes.SHA256())))
    return attest, struct.pack(">HH", T.ALG_ECDSA, T.ALG_SHA256) + tpm2b(r.to_bytes(32, "big")) + tpm2b(s.to_bytes(32, "big"))


def activate(ek_key, credential_blob: bytes, secret_blob: bytes, ak_name: bytes) -> bytes | None:
    """What the TPM does with TPM2_ActivateCredential for an ECC EK; None when the integrity check fails."""
    qe_x, qe_y = secret_blob[4:36], secret_blob[38:70]  # u16 size, u16 x size, x, u16 y size, y
    peer = ec.EllipticCurvePublicNumbers(int.from_bytes(qe_x, "big"), int.from_bytes(qe_y, "big"), ec.SECP256R1()).public_key()
    z = T.pad32(ek_key.exchange(ec.ECDH(), peer))
    ek_x = ek_key.public_key().public_numbers().x.to_bytes(32, "big")
    seed = hashlib.sha256(struct.pack(">I", 1) + z + b"IDENTITY\0" + qe_x + ek_x).digest()
    id_obj = credential_blob[2:]
    outer_len = struct.unpack(">H", id_obj[:2])[0]
    outer, enc = id_obj[2:2 + outer_len], id_obj[2 + outer_len:]
    expect = hmac.new(T.kdfa(seed, b"INTEGRITY", b"", b"", 256), enc + ak_name, hashlib.sha256).digest()
    if not hmac.compare_digest(outer, expect):
        return None
    dec = Cipher(algorithms.AES(T.kdfa(seed, b"STORAGE", ak_name, b"", 128)), modes.CFB(b"\0" * 16)).decryptor()
    plain = dec.update(enc) + dec.finalize()
    return plain[2:2 + struct.unpack(">H", plain[:2])[0]]


# ---- certificates -----------------------------------------------------------------------------------------------

NOW = datetime.datetime.now(datetime.timezone.utc)


def make_cert(subject_cn, key, issuer_cn, issuer_key, ca=False, pathlen=None, eku=None, maker=None, model=None, days=365,
              start_days=-1, same_name=True, serial=1, by_key_id=True):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]) if subject_cn else x509.Name([])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn if same_name else issuer_cn + " (other spelling)")])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key()).serial_number(serial)
         .not_valid_before(NOW + datetime.timedelta(days=start_days)).not_valid_after(NOW + datetime.timedelta(days=days)))
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
    if by_key_id:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    if ca:
        b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([ObjectIdentifier(eku)]), critical=False)
    if maker:
        attrs = [x509.NameAttribute(ObjectIdentifier("2.23.133.2.1"), "id:" + maker.encode().hex().upper())]
        if model:
            attrs.append(x509.NameAttribute(ObjectIdentifier("2.23.133.2.2"), model))
        b = b.add_extension(x509.SubjectAlternativeName([x509.DirectoryName(x509.Name(attrs))]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


class Pki:
    """A manufacturer root, an intermediate, and an EK certificate for a pretend TPM."""

    def __init__(self, **ek_options):
        self.root_key, self.mid_key, self.ek_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
        self.root = make_cert("Test TPM Root", self.root_key, "Test TPM Root", self.root_key, ca=True, days=3650, by_key_id=False)
        self.mid = make_cert("Test TPM CA", self.mid_key, "Test TPM Root", self.root_key, ca=True, pathlen=0, days=3000)
        opts = dict(eku="2.23.133.8.1", maker="TEST", model="T-1000")
        opts.update(ek_options)
        self.ek = make_cert("", self.ek_key, "Test TPM CA", self.mid_key, **opts)
        self.tmp = tempfile.TemporaryDirectory()
        self.root_file = os.path.join(self.tmp.name, "root.pem")
        with open(self.root_file, "wb") as f:
            f.write(self.root.public_bytes(serialization.Encoding.PEM))

    def chain(self):
        return [der(self.ek), der(self.mid)]


class ChainTest(unittest.TestCase):
    def test_a_good_chain_gives_the_ek_point_and_the_maker(self):
        pki = Pki()
        ek = T.verify_ek_chain(pki.chain(), [pki.root_file])
        self.assertIsNotNone(ek)
        nums = pki.ek_key.public_key().public_numbers()
        self.assertEqual((ek["x"], ek["y"]), (nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big")))
        self.assertEqual((ek["manufacturer"], ek["model"]), ("TEST", "T-1000"))

    def test_a_chain_with_the_root_included_also_works(self):
        pki = Pki()
        self.assertIsNotNone(T.verify_ek_chain(pki.chain() + [der(pki.root)], [pki.root_file]))

    def test_issuers_are_found_by_key_identifier_when_the_names_differ(self):
        pki = Pki()
        ek = make_cert("", pki.ek_key, "Test TPM CA", pki.mid_key, eku="2.23.133.8.1", maker="AMD", same_name=False)
        self.assertIsNotNone(T.verify_ek_chain([der(ek), der(pki.mid)], [pki.root_file]))

    def test_an_untrusted_root_is_refused(self):
        pki, other = Pki(), Pki()
        self.assertIsNone(T.verify_ek_chain(pki.chain(), [other.root_file]))
        self.assertIsNone(T.verify_ek_chain(pki.chain(), []))

    def test_a_missing_intermediate_is_refused(self):
        pki = Pki()
        self.assertIsNone(T.verify_ek_chain([der(pki.ek)], [pki.root_file]))

    def test_a_tampered_certificate_is_refused(self):
        pki = Pki()
        raw = bytearray(der(pki.ek))
        raw[len(raw) // 2] ^= 0x01
        self.assertIsNone(T.verify_ek_chain([bytes(raw), der(pki.mid)], [pki.root_file]))

    def test_a_certificate_signed_by_the_wrong_key_is_refused(self):
        pki = Pki()
        forged = make_cert("", pki.ek_key, "Test TPM CA", ec.generate_private_key(ec.SECP256R1()), eku="2.23.133.8.1")
        self.assertIsNone(T.verify_ek_chain([der(forged), der(pki.mid)], [pki.root_file]))

    def test_expired_and_not_yet_valid_certificates_are_refused(self):
        pki = Pki(days=-1, start_days=-30)
        self.assertIsNone(T.verify_ek_chain(pki.chain(), [pki.root_file]))
        pki = Pki(days=30, start_days=10)
        self.assertIsNone(T.verify_ek_chain(pki.chain(), [pki.root_file]))

    def test_the_wrong_key_usage_is_refused(self):
        pki = Pki(eku="1.3.6.1.5.5.7.3.1")
        self.assertIsNone(T.verify_ek_chain(pki.chain(), [pki.root_file]))

    def test_an_ek_that_is_not_p256_is_refused(self):
        pki = Pki()
        pki.ek_key = rsa.generate_private_key(65537, 2048)
        ek = make_cert("", pki.ek_key, "Test TPM CA", pki.mid_key, eku="2.23.133.8.1")
        self.assertIsNone(T.verify_ek_chain([der(ek), der(pki.mid)], [pki.root_file]))

    def test_an_intermediate_that_is_not_a_ca_is_refused(self):
        pki = Pki()
        mid = make_cert("Test TPM CA", pki.mid_key, "Test TPM Root", pki.root_key, ca=False)
        self.assertIsNone(T.verify_ek_chain([der(pki.ek), der(mid)], [pki.root_file]))

    def test_a_path_length_that_is_exceeded_is_refused(self):
        pki = Pki()
        mid = make_cert("Test TPM CA", pki.mid_key, "Test TPM Root", pki.root_key, ca=True, pathlen=0)
        sub_key = ec.generate_private_key(ec.SECP256R1())
        sub = make_cert("Test Sub CA", sub_key, "Test TPM CA", pki.mid_key, ca=True, pathlen=0)
        ek = make_cert("", pki.ek_key, "Test Sub CA", sub_key, eku="2.23.133.8.1")
        self.assertIsNone(T.verify_ek_chain([der(ek), der(sub), der(mid)], [pki.root_file]))

    def test_garbage_and_too_many_certificates_are_refused(self):
        pki = Pki()
        self.assertIsNone(T.verify_ek_chain([b"not a certificate"], [pki.root_file]))
        self.assertIsNone(T.verify_ek_chain([], [pki.root_file]))
        self.assertIsNone(T.verify_ek_chain([der(pki.ek)] * 9, [pki.root_file]))
        self.assertIsNone(T.verify_ek_chain([der(pki.ek), b"x" * 9000], [pki.root_file]))

    def test_the_shipped_roots_load(self):
        names = [os.path.basename(f) for f in T.root_files()]
        self.assertIn("intel-ondie-ca-root.pem", names)
        self.assertEqual(len(T._load_roots(T.root_files())), 2)


class CredentialTest(unittest.TestCase):
    def test_only_the_tpm_with_the_ek_and_the_ak_name_recovers_the_secret(self):
        ek_key = ec.generate_private_key(ec.SECP256R1())
        nums = ek_key.public_key().public_numbers()
        ak_name = T.name(b"an attestation key's public area")
        secret = os.urandom(32)
        cred = T.make_credential(nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big"), ak_name, secret)
        self.assertEqual(activate(ek_key, cred["credential_blob"], cred["secret"], ak_name), secret)
        self.assertIsNone(activate(ek_key, cred["credential_blob"], cred["secret"], T.name(b"another key")))  # other AK
        other_ek = ec.generate_private_key(ec.SECP256R1())
        try:
            self.assertNotEqual(activate(other_ek, cred["credential_blob"], cred["secret"], ak_name), secret)  # other chip
        except Exception:
            pass

    def test_short_secrets_work_and_bad_sizes_are_refused(self):
        ek_key = ec.generate_private_key(ec.SECP256R1())
        nums = ek_key.public_key().public_numbers()
        x, y, name = nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big"), T.name(b"ak")
        self.assertEqual(activate(ek_key, *(lambda c: (c["credential_blob"], c["secret"]))(T.make_credential(x, y, name, b"abc")), name), b"abc")
        for bad in (b"", b"x" * 33):
            with self.assertRaises(T.TpmProofError):
                T.make_credential(x, y, name, bad)

    def test_every_challenge_is_different(self):
        ek_key = ec.generate_private_key(ec.SECP256R1())
        nums = ek_key.public_key().public_numbers()
        a = T.make_credential(nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big"), T.name(b"ak"), b"s" * 32)
        b = T.make_credential(nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big"), T.name(b"ak"), b"s" * 32)
        self.assertNotEqual(a["secret"], b["secret"])


GOOD_AK = T.ATTR_FIXEDTPM | T.ATTR_FIXEDPARENT | T.ATTR_RESTRICTED | T.ATTR_SIGN
GOOD_KEY = T.ATTR_FIXEDTPM | T.ATTR_FIXEDPARENT | T.ATTR_SENSITIVEDATAORIGIN | T.ATTR_SIGN


class CertificationTest(unittest.TestCase):
    def setUp(self):
        self.ak_key = ec.generate_private_key(ec.SECP256R1())
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.ak_pub = public_area(self.ak_key, GOOD_AK, scheme=True)
        self.key_pub = public_area(self.key, GOOD_KEY)
        self.nonce = ("N" * 43).encode()

    def verify(self, attest=None, sig=None, ak_pub=None, key_pub=None, nonce=None, submitted=None):
        a, s = certify(self.ak_key, self.key_pub, self.nonce)
        return T.verify_certification(ak_pub or self.ak_pub, attest or a, sig or s, key_pub or self.key_pub,
                                      nonce or self.nonce, submitted or spki(self.key))

    def test_a_good_certification_is_accepted(self):
        self.assertIsNone(self.verify())

    def test_a_longer_nonce_may_come_back_hashed(self):
        attest, sig = certify(self.ak_key, self.key_pub, hashlib.sha256(self.nonce).digest())
        self.assertIsNone(self.verify(attest, sig))

    def test_another_enrolment_nonce_is_refused(self):
        self.assertEqual(self.verify(nonce=("X" * 43).encode()), "certification is not bound to this enrolment")

    def test_another_submitted_key_is_refused(self):
        other = ec.generate_private_key(ec.SECP256R1())
        self.assertEqual(self.verify(submitted=spki(other)), "certified key is not the submitted key")
        self.assertEqual(self.verify(submitted=b"junk"), "certified key is not the submitted key")

    def test_a_certification_signed_by_another_key_is_refused(self):
        attest, sig = certify(ec.generate_private_key(ec.SECP256R1()), self.key_pub, self.nonce)
        self.assertEqual(self.verify(attest, sig), "bad certification signature")

    def test_a_changed_attestation_is_refused(self):
        attest, sig = certify(self.ak_key, self.key_pub, self.nonce)
        self.assertEqual(self.verify(attest[:-1] + bytes([attest[-1] ^ 1]), sig), "bad certification signature")

    def test_a_certified_name_that_is_not_this_key_is_refused(self):
        attest, sig = certify(self.ak_key, self.key_pub, self.nonce, name=T.name(b"some other key"))
        self.assertEqual(self.verify(attest, sig), "certified name does not match the key")

    def test_not_a_certification_is_refused(self):
        for kw in ({"magic": 0x12345678}, {"typ": 0x8014}):
            attest, sig = certify(self.ak_key, self.key_pub, self.nonce, **kw)
            self.assertEqual(self.verify(attest, sig), "not a TPM certification")
        attest, sig = certify(self.ak_key, self.key_pub, self.nonce, trailing=b"x")
        self.assertEqual(self.verify(attest, sig), "trailing bytes in the attestation")

    def test_the_attestation_key_must_be_restricted_and_fixed(self):
        for attrs in (GOOD_AK & ~T.ATTR_RESTRICTED, GOOD_AK & ~T.ATTR_FIXEDTPM, GOOD_AK | T.ATTR_DECRYPT, GOOD_AK & ~T.ATTR_SIGN):
            reason = self.verify(ak_pub=public_area(self.ak_key, attrs, scheme=True))
            self.assertEqual(reason, "attestation key is not a restricted, fixed signing key", hex(attrs))

    def test_the_signing_key_must_be_born_in_and_fixed_to_the_tpm(self):
        for attrs in (GOOD_KEY & ~T.ATTR_SENSITIVEDATAORIGIN, GOOD_KEY & ~T.ATTR_FIXEDPARENT, GOOD_KEY | T.ATTR_RESTRICTED,
                      GOOD_KEY | T.ATTR_DECRYPT):
            key_pub = public_area(self.key, attrs)
            attest, sig = certify(self.ak_key, key_pub, self.nonce)
            self.assertEqual(self.verify(attest, sig, key_pub=key_pub), "signing key is not fixed to the TPM", hex(attrs))

    def test_unparseable_input_is_refused_not_a_crash(self):
        self.assertEqual(self.verify(ak_pub=b"\x00\x23"), "unparseable public area")
        attest, sig = certify(self.ak_key, self.key_pub, self.nonce)
        self.assertEqual(self.verify(attest, b"\x00\x18\x00"), "unparseable signature")
        self.assertEqual(self.verify(attest, struct.pack(">HH", 0x0014, T.ALG_SHA256) + tpm2b(b"r") + tpm2b(b"s")), "unexpected signature algorithm")
        self.assertEqual(self.verify(attest=b"\xff\x54\x43"), "bad certification signature")

    def test_only_p256_sha256_ecc_public_areas_parse(self):
        with self.assertRaises(T.TpmProofError):
            T.parse_public(struct.pack(">HHI", 0x0001, T.ALG_SHA256, 0) + tpm2b(b""))  # RSA
        with self.assertRaises(T.TpmProofError):
            T.parse_public(self.key_pub + b"x")


if __name__ == "__main__":
    unittest.main()
