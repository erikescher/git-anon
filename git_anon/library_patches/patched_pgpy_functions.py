from datetime import datetime

from pgpy import PGPKey, PGPUID, PGPSignature
from pgpy.constants import SignatureType, HashAlgorithm, Features

# flake8: noqa


# The following is a patched version of pgpy.pgp.PGPKey:add_uid version 0.5.2
# this function is only patched to be compatible with patched_pgpy_certify
def patched_pgpy_add_uid(self, uid, selfsign=True, **prefs):
    """
    Add a User ID to this key.

    :param uid: The user id to add
    :type uid: :py:obj:`~pgpy.PGPUID`
    :param selfsign: Whether or not to self-sign the user id before adding it
    :type selfsign: ``bool``

    Valid optional keyword arguments are identical to those of self-signatures for :py:meth:`PGPKey.certify`.
    Any such keyword arguments are ignored if selfsign is ``False``
    """
    uid._parent = self
    if selfsign:
        uid |= patched_pgpy_certify(self, uid, SignatureType.Positive_Cert, **prefs)

    self |= uid


# The following is a patched version of pgpy.pgp.PGPKey:certify version 0.5.2
# The only change is that the "created" parameter is passed to Signature.new(), where it will be used.
def patched_pgpy_certify(self, subject, level=SignatureType.Generic_Cert, **prefs):
    """
    Sign a key or a user id within a key.

    :param subject: The user id or key to be certified.
    :type subject: :py:obj:`PGPKey`, :py:obj:`PGPUID`
    :param level: :py:obj:`~constants.SignatureType.Generic_Cert`, :py:obj:`~constants.SignatureType.Persona_Cert`,
                  :py:obj:`~constants.SignatureType.Casual_Cert`, or :py:obj:`~constants.SignatureType.Positive_Cert`.
                  Only used if subject is a :py:obj:`PGPUID`; otherwise, it is ignored.
    :raises: :py:exc:`~pgpy.errors.PGPError` if the key is passphrase-protected and has not been unlocked
    :raises: :py:exc:`~pgpy.errors.PGPError` if the key is public
    :returns: :py:obj:`PGPSignature`

    In addition to the optional keyword arguments accepted by :py:meth:`PGPKey.sign`, the following optional
    keyword arguments can be used with :py:meth:`PGPKey.certify`.

    These optional keywords only make sense, and thus only have an effect, when self-signing a key or User ID:

    :keyword usage: A ``set`` of key usage flags, as :py:obj:`~constants.KeyFlags`.
                    This keyword is ignored for non-self-certifications.
    :type usage: ``set``
    :keyword ciphers: A list of preferred symmetric ciphers, as :py:obj:`~constants.SymmetricKeyAlgorithm`.
                      This keyword is ignored for non-self-certifications.
    :type ciphers: ``list``
    :keyword hashes: A list of preferred hash algorithms, as :py:obj:`~constants.HashAlgorithm`.
                     This keyword is ignored for non-self-certifications.
    :type hashes: ``list``
    :keyword compression: A list of preferred compression algorithms, as :py:obj:`~constants.CompressionAlgorithm`.
                          This keyword is ignored for non-self-certifications.
    :type compression: ``list``
    :keyword key_expiration: Specify a key expiration date for when this key should expire, or a
                          :py:obj:`~datetime.timedelta` of how long after the key was created it should expire.
                          This keyword is ignored for non-self-certifications.
    :type key_expiration: :py:obj:`datetime.datetime`, :py:obj:`datetime.timedelta`
    :keyword keyserver: Specify the URI of the preferred key server of the user.
                        This keyword is ignored for non-self-certifications.
    :type keyserver: ``str``, ``unicode``, ``bytes``
    :keyword primary: Whether or not to consider the certified User ID as the primary one.
                      This keyword is ignored for non-self-certifications, and any certifications directly on keys.
    :type primary: ``bool``

    These optional keywords only make sense, and thus only have an effect, when signing another key or User ID:

    :keyword trust: Specify the level and amount of trust to assert when certifying a public key. Should be a tuple
                    of two ``int`` s, specifying the trust level and trust amount. See
                    `RFC 4880 Section 5.2.3.13. Trust Signature <https://tools.ietf.org/html/rfc4880#section-5.2.3.13>`_
                    for more on what these values mean.
    :type trust: ``tuple`` of two ``int`` s
    :keyword regex: Specify a regular expression to constrain the specified trust signature in the resulting signature.
                    Symbolically signifies that the specified trust signature only applies to User IDs which match
                    this regular expression.
                    This is meaningless without also specifying trust level and amount.
    :type regex: ``str``
    """
    hash_algo = prefs.pop('hash', None)
    sig_type = level
    if isinstance(subject, PGPKey):
        sig_type = SignatureType.DirectlyOnKey

    created = prefs.pop('created', None)
    sig = PGPSignature.new(sig_type, self.key_algorithm, hash_algo, self.fingerprint.keyid, created=created)

    # signature options that only make sense in certifications
    usage = prefs.pop('usage', None)
    exportable = prefs.pop('exportable', None)

    if usage is not None:
        sig._signature.subpackets.addnew('KeyFlags', hashed=True, flags=usage)

    if exportable is not None:
        sig._signature.subpackets.addnew('ExportableCertification', hashed=True, bflag=exportable)

    keyfp = self.fingerprint
    if isinstance(subject, PGPKey):
        keyfp = subject.fingerprint
    if isinstance(subject, PGPUID) and subject._parent is not None:
        keyfp = subject._parent.fingerprint

    if keyfp == self.fingerprint:
        # signature options that only make sense in self-certifications
        cipher_prefs = prefs.pop('ciphers', None)
        hash_prefs = prefs.pop('hashes', None)
        compression_prefs = prefs.pop('compression', None)
        key_expires = prefs.pop('key_expiration', None)
        keyserver_flags = prefs.pop('keyserver_flags', None)
        keyserver = prefs.pop('keyserver', None)
        primary_uid = prefs.pop('primary', None)

        if key_expires is not None:
            # key expires should be a timedelta, so if it's a datetime, turn it into a timedelta
            if isinstance(key_expires, datetime):
                key_expires = key_expires - self.created

            sig._signature.subpackets.addnew('KeyExpirationTime', hashed=True, expires=key_expires)

        if cipher_prefs is not None:
            sig._signature.subpackets.addnew('PreferredSymmetricAlgorithms', hashed=True, flags=cipher_prefs)

        if hash_prefs:
            sig._signature.subpackets.addnew('PreferredHashAlgorithms', hashed=True, flags=hash_prefs)
            if sig.hash_algorithm is None:
                sig._signature.halg = hash_prefs[0]
        if sig.hash_algorithm is None:
            sig._signature.halg = HashAlgorithm.SHA256

        if compression_prefs is not None:
            sig._signature.subpackets.addnew('PreferredCompressionAlgorithms', hashed=True, flags=compression_prefs)

        if keyserver_flags is not None:
            sig._signature.subpackets.addnew('KeyServerPreferences', hashed=True, flags=keyserver_flags)

        if keyserver is not None:
            sig._signature.subpackets.addnew('PreferredKeyServer', hashed=True, uri=keyserver)

        if primary_uid is not None:
            sig._signature.subpackets.addnew('PrimaryUserID', hashed=True, primary=primary_uid)

        # Features is always set on self-signatures
        sig._signature.subpackets.addnew('Features', hashed=True, flags=Features.pgpy_features)

    else:
        # signature options that only make sense in non-self-certifications
        trust = prefs.pop('trust', None)
        regex = prefs.pop('regex', None)

        if trust is not None:
            sig._signature.subpackets.addnew('TrustSignature', hashed=True, level=trust[0], amount=trust[1])

            if regex is not None:
                sig._signature.subpackets.addnew('RegularExpression', hashed=True, regex=regex)

    return self._sign(subject, sig, **prefs)


def patched_pgpy_sign(key: PGPKey, subject, **prefs):
    # pylint: disable=protected-access
    sig = PGPSignature.new(SignatureType.BinaryDocument, key.key_algorithm, None, key.fingerprint.keyid)
    # noinspection PyProtectedMember
    return key._sign(subject, sig, **prefs)