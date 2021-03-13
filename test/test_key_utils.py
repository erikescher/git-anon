import textwrap
from unittest import TestCase

import pgpy
from pgpy import PGPKey, PGPUID

from git_anon.gpg_general.key_utils import KeyUtils

CERTIFIER = """
    -----BEGIN PGP PRIVATE KEY BLOCK-----
    
    xcA4BF9pxEABAgCz5BHqk2BkO8jjFxj9sl6g2oBQRVRReXA+ViXq/u9eFGn8VOyb
    wD8iP4RtrBUCXzet/HeCdZ1/A7psTQAY6gRFABEBAAEAAf98mR7zvCqKooItEKWF
    qxMyFMXFU4/octWUx7SxxOxk21KVw3RaIBx4H2msAekX9hOUFMurXhAaaexf8ONb
    OCehAQDpG3B4omlVCuXk/OVzgnN9K5r9aoZI3EiNLJ05+JbVuQEAxY63j5UWM652
    /VOqnNHLzK3nxmWYHGlUruYtsDuLaO0A/2l8N290hceGuKjfNUgwPoq/HdJijgG3
    Gce7EhAE5pYjU6DNJ0Nhbid0IHNpZ24gd2l0aG91dCBhIFVJRC1TZWxmLVNpZ25h
    dHVyZcJfBBMBCAAJBQJfacRAAh4BAAoJELVPKvs8ars7KCYB/3+fojSGT7f/dTjq
    4mdRD+5wsrKZlwBs40IFjXUEbXjjpV1rRpNC+aHFXB9jAjtRv8wOvy5xgD5f4EMm
    WlVmL4Y=
    =OJzv
    -----END PGP PRIVATE KEY BLOCK-----"""

KEY_COMPLETE = """
    -----BEGIN PGP PRIVATE KEY BLOCK-----
    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
    =Ym5k
    -----END PGP PRIVATE KEY BLOCK-----
    """

KEY_COMPLETE_old = """
    -----BEGIN PGP PRIVATE KEY BLOCK-----
    
    xcA4BF9pxEABAgDktFGyE9nB8ufZAhG/R6CC1X5PrFi0tOFVOWkVLUdxf4exgh8I
    F/55ykjUTbnhaWFJ5Q2C5fsDjs7Ym0OZjadvABEBAAEAAgDI3RIPW93ZuJQmBOo/
    XBI+NnGcWhsCgwaQyj5figgARj9RwNZ05F4zOfVfqR5fKCKmcEHxdRKxrTfy+ZIk
    Cz+BAQD5vQwq8OZPiYRDU9MhJDqujAtmdG6w3I0DYVBO3jbTwQEA6nBDhELW2XI5
    HKK1v+z4QF1DCXhVFjyNNzemThBShy8BAIiGlyoUe+dYY80SurBT6ll3DZ4nB0eR
    7u2Z9cyomh07SCPCXAQfAQgABgUCX2nEQAAKCRC1Tyr7PGq7O8ZJAgCH4mOWRR7B
    k2tSRw4GHqM8F7laUJEuQH9NvUjYxr09tJ2ASGrMbj1XIpmVTKp3uVOuQMulCkdi
    3cjckGXoHVIFzQ1DZXJ0aWZpZWQgVUlEwl8EEwEIAAkFAl9pxEACHgEACgkQpbWT
    yTMucG3H5gIA3Cfj1y0zTa4AZtB4MZd/dWBhVnNwWi6KQ8b1FVcAHwe8K8NhyF2A
    QMr9HT77ZSwSQ+f0Wr+Y/Geeq8LNBTtj7sJcBBABCAAGBQJfacRAAAoJELVPKvs8
    ars7/WoB/1QjdIrYKyTTihSycyMIurGkYuIqqpyI6/qFOoZmAt/htfadk1F5/ghO
    a1hoflynnIm9thFyTl09RlVbC1ii86HNDUR1cGxpY2F0ZSBVSUTCXwQTAQgACQUC
    X2nEQAIeAQAKCRCltZPJMy5wbUwuAgCg4HHK7oRMKfSrC/jvuX7IMZTFMCGaaVD9
    uQJ7QqpJeBhZ9ni9sMGEXhXvcJ7Z+CSEtGngBnnHCIg9EWFBBOcVzQ1EdXBsaWNh
    dGUgVUlEwl8EEwEIAAkFAl9pxEACHgEACgkQpbWTyTMucG1MLgIAoOBxyu6ETCn0
    qwv477l+yDGUxTAhmmlQ/bkCe0KqSXgYWfZ4vbDBhF4V73Ce2fgkhLRp4AZ5xwiI
    PRFhQQTnFc0KU2Vjb25kIFVJRMJfBBMBCAAJBQJfacRAAh4BAAoJEKW1k8kzLnBt
    0iQB/imuxDqi/N81U0ROI9p8CFinb/3e/15ELWW5yPZYoPrbrejtK6vDrwpw+CVK
    vWKeGkxqDMqoTWwndI8bGeKsQPjNCUZpcnN0IFVJRMJfBBMBCAAJBQJfacRAAh4B
    AAoJEKW1k8kzLnBtdGwCAJI8hUWCF21lS7GjNUGVwyKCf/3cFQzBmijihHLUYxoi
    scZ/PLTL9Dn8WzRZ2ns25R4PmNwT16Ex0O9yqBqWUbk=
    =Nkc7
    -----END PGP PRIVATE KEY BLOCK-----"""

KEY_SIGNATURES_STRIPPED = """
    -----BEGIN PGP PRIVATE KEY BLOCK-----
    
    xcA4BF9pxEABAgDktFGyE9nB8ufZAhG/R6CC1X5PrFi0tOFVOWkVLUdxf4exgh8I
    F/55ykjUTbnhaWFJ5Q2C5fsDjs7Ym0OZjadvABEBAAEAAgDI3RIPW93ZuJQmBOo/
    XBI+NnGcWhsCgwaQyj5figgARj9RwNZ05F4zOfVfqR5fKCKmcEHxdRKxrTfy+ZIk
    Cz+BAQD5vQwq8OZPiYRDU9MhJDqujAtmdG6w3I0DYVBO3jbTwQEA6nBDhELW2XI5
    HKK1v+z4QF1DCXhVFjyNNzemThBShy8BAIiGlyoUe+dYY80SurBT6ll3DZ4nB0eR
    7u2Z9cyomh07SCPNCUZpcnN0IFVJRMJfBBMBCAAJBQJfacRAAh4BAAoJEKW1k8kz
    LnBtdGwCAJI8hUWCF21lS7GjNUGVwyKCf/3cFQzBmijihHLUYxoiscZ/PLTL9Dn8
    WzRZ2ns25R4PmNwT16Ex0O9yqBqWUbnNClNlY29uZCBVSUTCXwQTAQgACQUCX2nE
    QAIeAQAKCRCltZPJMy5wbdIkAf4prsQ6ovzfNVNETiPafAhYp2/93v9eRC1lucj2
    WKD6263o7Surw68KcPglSr1inhpMagzKqE1sJ3SPGxnirED4zQ1EdXBsaWNhdGUg
    VUlEwl8EEwEIAAkFAl9pxEACHgEACgkQpbWTyTMucG1MLgIAoOBxyu6ETCn0qwv4
    77l+yDGUxTAhmmlQ/bkCe0KqSXgYWfZ4vbDBhF4V73Ce2fgkhLRp4AZ5xwiIPRFh
    QQTnFc0NRHVwbGljYXRlIFVJRMJfBBMBCAAJBQJfacRAAh4BAAoJEKW1k8kzLnBt
    TC4CAKDgccruhEwp9KsL+O+5fsgxlMUwIZppUP25AntCqkl4GFn2eL2wwYReFe9w
    ntn4JIS0aeAGeccIiD0RYUEE5xXNDUNlcnRpZmllZCBVSUTCXAQQAQgABgUCX2nE
    QAAKCRC1Tyr7PGq7O/1qAf9UI3SK2Csk04oUsnMjCLqxpGLiKqqciOv6hTqGZgLf
    4bX2nZNRef4ITmtYaH5cp5yJvbYRck5dPUZVWwtYovOhwl8EEwEIAAkFAl9pxEAC
    HgEACgkQpbWTyTMucG3H5gIA3Cfj1y0zTa4AZtB4MZd/dWBhVnNwWi6KQ8b1FVcA
    Hwe8K8NhyF2AQMr9HT77ZSwSQ+f0Wr+Y/Geeq8LNBTtj7sfAOARfac0jAQIAurDG
    pJAh8X1jQchkO9xXYm6dKAY0+pGkji1a19VabUpp1m7a+wdZNlGCBSgyT18Csz+2
    GpgOp8u6XBFdraNYOwARAQABAAIArrqpEHh97GFotrbxaT1O5CeXG1DD4QjTNOaq
    MXvUSJhUP5zSenfJfec3lH6ROSx3X7z+sumGSLbjj3XkxK/4gQEA7jIdr5XBZT7H
    OCkW/Uhrmsrvjd7gT9zE1a0Q5bqlvSEBAMilGwd9K48xTuI6/8vLkfeC/k2DIIXH
    4Ak1noeuY+3bAP9HwjrGb3f/qACdZx45KP1SHVLI44/NwY3DsZflcuhmg1lcwroE
    GAEIAAYFAl9pzSMAaAkQpbWTyTMucG1dIAQZAQgABgUCX2nNIwAKCRCb/5Ar8zhi
    w4cGAf9BNF6XSN3Oo0IYzHlAfOk4kr0A5R74FdGSLIQYBgAOcZ3RrY9gwlP+zkS1
    tV2vJPwvSUAaY8oW04/MUi55NUdj6ywCAMmHgXPkVcu7RIgPa/CoKmp0OWau/U34
    FAVJ4+DftiDz/ympk6Fr/KiX+K2fbl9sZunjTZ7voxJrwu6ok/fEACs=
    =ywm9
    -----END PGP PRIVATE KEY BLOCK-----
    """

KEY_UIDS_STRIPPED = """
    -----BEGIN PGP PRIVATE KEY BLOCK-----
    
    xcA4BF9pxEABAgDktFGyE9nB8ufZAhG/R6CC1X5PrFi0tOFVOWkVLUdxf4exgh8I
    F/55ykjUTbnhaWFJ5Q2C5fsDjs7Ym0OZjadvABEBAAEAAgDI3RIPW93ZuJQmBOo/
    XBI+NnGcWhsCgwaQyj5figgARj9RwNZ05F4zOfVfqR5fKCKmcEHxdRKxrTfy+ZIk
    Cz+BAQD5vQwq8OZPiYRDU9MhJDqujAtmdG6w3I0DYVBO3jbTwQEA6nBDhELW2XI5
    HKK1v+z4QF1DCXhVFjyNNzemThBShy8BAIiGlyoUe+dYY80SurBT6ll3DZ4nB0eR
    7u2Z9cyomh07SCPCXAQfAQgABgUCX2nEQAAKCRC1Tyr7PGq7O8ZJAgCH4mOWRR7B
    k2tSRw4GHqM8F7laUJEuQH9NvUjYxr09tJ2ASGrMbj1XIpmVTKp3uVOuQMulCkdi
    3cjckGXoHVIFx8A4BF9pzSMBAgC6sMakkCHxfWNByGQ73Fdibp0oBjT6kaSOLVrX
    1VptSmnWbtr7B1k2UYIFKDJPXwKzP7YamA6ny7pcEV2to1g7ABEBAAEAAgCuuqkQ
    eH3sYWi2tvFpPU7kJ5cbUMPhCNM05qoxe9RImFQ/nNJ6d8l95zeUfpE5LHdfvP6y
    6YZItuOPdeTEr/iBAQDuMh2vlcFlPsc4KRb9SGuayu+N3uBP3MTVrRDluqW9IQEA
    yKUbB30rjzFO4jr/y8uR94L+TYMghcfgCTWeh65j7dsA/0fCOsZvd/+oAJ1nHjko
    /VIdUsjjj83BjcOxl+Vy6GaDWVzCugQYAQgABgUCX2nNIwBoCRCltZPJMy5wbV0g
    BBkBCAAGBQJfac0jAAoJEJv/kCvzOGLDhwYB/0E0XpdI3c6jQhjMeUB86TiSvQDl
    HvgV0ZIshBgGAA5xndGtj2DCU/7ORLW1Xa8k/C9JQBpjyhbTj8xSLnk1R2PrLAIA
    yYeBc+RVy7tEiA9r8KgqanQ5Zq79TfgUBUnj4N+2IPP/KamToWv8qJf4rZ9uX2xm
    6eNNnu+jEmvC7qiT98QAKw==
    =ZNP0
    -----END PGP PRIVATE KEY BLOCK-----
    """

KEY_SUBKEYS_STRIPPED = """
    -----BEGIN PGP PRIVATE KEY BLOCK-----
    
    xcA4BF9pxEABAgDktFGyE9nB8ufZAhG/R6CC1X5PrFi0tOFVOWkVLUdxf4exgh8I
    F/55ykjUTbnhaWFJ5Q2C5fsDjs7Ym0OZjadvABEBAAEAAgDI3RIPW93ZuJQmBOo/
    XBI+NnGcWhsCgwaQyj5figgARj9RwNZ05F4zOfVfqR5fKCKmcEHxdRKxrTfy+ZIk
    Cz+BAQD5vQwq8OZPiYRDU9MhJDqujAtmdG6w3I0DYVBO3jbTwQEA6nBDhELW2XI5
    HKK1v+z4QF1DCXhVFjyNNzemThBShy8BAIiGlyoUe+dYY80SurBT6ll3DZ4nB0eR
    7u2Z9cyomh07SCPCXAQfAQgABgUCX2nEQAAKCRC1Tyr7PGq7O8ZJAgCH4mOWRR7B
    k2tSRw4GHqM8F7laUJEuQH9NvUjYxr09tJ2ASGrMbj1XIpmVTKp3uVOuQMulCkdi
    3cjckGXoHVIFzQlGaXJzdCBVSUTCXwQTAQgACQUCX2nEQAIeAQAKCRCltZPJMy5w
    bXRsAgCSPIVFghdtZUuxozVBlcMign/93BUMwZoo4oRy1GMaIrHGfzy0y/Q5/Fs0
    Wdp7NuUeD5jcE9ehMdDvcqgallG5zQpTZWNvbmQgVUlEwl8EEwEIAAkFAl9pxEAC
    HgEACgkQpbWTyTMucG3SJAH+Ka7EOqL83zVTRE4j2nwIWKdv/d7/XkQtZbnI9lig
    +tut6O0rq8OvCnD4JUq9Yp4aTGoMyqhNbCd0jxsZ4qxA+M0NRHVwbGljYXRlIFVJ
    RMJfBBMBCAAJBQJfacRAAh4BAAoJEKW1k8kzLnBtTC4CAKDgccruhEwp9KsL+O+5
    fsgxlMUwIZppUP25AntCqkl4GFn2eL2wwYReFe9wntn4JIS0aeAGeccIiD0RYUEE
    5xXNDUR1cGxpY2F0ZSBVSUTCXwQTAQgACQUCX2nEQAIeAQAKCRCltZPJMy5wbUwu
    AgCg4HHK7oRMKfSrC/jvuX7IMZTFMCGaaVD9uQJ7QqpJeBhZ9ni9sMGEXhXvcJ7Z
    +CSEtGngBnnHCIg9EWFBBOcVzQ1DZXJ0aWZpZWQgVUlEwlwEEAEIAAYFAl9pxEAA
    CgkQtU8q+zxquzv9agH/VCN0itgrJNOKFLJzIwi6saRi4iqqnIjr+oU6hmYC3+G1
    9p2TUXn+CE5rWGh+XKecib22EXJOXT1GVVsLWKLzocJfBBMBCAAJBQJfacRAAh4B
    AAoJEKW1k8kzLnBtx+YCANwn49ctM02uAGbQeDGXf3VgYVZzcFouikPG9RVXAB8H
    vCvDYchdgEDK/R0++2UsEkPn9Fq/mPxnnqvCzQU7Y+4=
    =O9H2
    -----END PGP PRIVATE KEY BLOCK-----
    """

KEY_FULLY_STRIPPED = """
    -----BEGIN PGP PRIVATE KEY BLOCK-----

    xcA4BF9pxEABAgDktFGyE9nB8ufZAhG/R6CC1X5PrFi0tOFVOWkVLUdxf4exgh8I
    F/55ykjUTbnhaWFJ5Q2C5fsDjs7Ym0OZjadvABEBAAEAAgDI3RIPW93ZuJQmBOo/
    XBI+NnGcWhsCgwaQyj5figgARj9RwNZ05F4zOfVfqR5fKCKmcEHxdRKxrTfy+ZIk
    Cz+BAQD5vQwq8OZPiYRDU9MhJDqujAtmdG6w3I0DYVBO3jbTwQEA6nBDhELW2XI5
    HKK1v+z4QF1DCXhVFjyNNzemThBShy8BAIiGlyoUe+dYY80SurBT6ll3DZ4nB0eR
    7u2Z9cyomh07SCM=
    =u642
    -----END PGP PRIVATE KEY BLOCK-----
    """


class TestKeyUtils(TestCase):

    @staticmethod
    def _create_key() -> None:
        certifier = PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, 512)
        certifier.add_uid(PGPUID.new("Can't sign without a UID-Self-Signature"), selfsign=True)
        key = PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, 512)
        key.add_uid(PGPUID.new("First UID"), selfsign=True)
        key.add_uid(PGPUID.new("Second UID"), selfsign=True)
        key.add_uid(PGPUID.new("Duplicate UID"), selfsign=True)
        key.add_uid(PGPUID.new("Duplicate UID"), selfsign=True)
        # key.add_uid(PGPUID.new("Unsigned UID"), selfsign=False)

        certified_uid = PGPUID.new("Certified UID")
        key.add_uid(certified_uid, selfsign=True)

        key |= certifier.certify(key)

        certified_uid |= certifier.certify(key.get_uid("Certified UID"))

        print(certifier)

        print(key)

    @staticmethod
    def get_stored_key(armored_key: str) -> PGPKey:
        return PGPKey.from_blob(textwrap.dedent(armored_key))[0]

    def assertSerializedEqual(self, one, two):
        self.assertEqual(str(one), str(two))
        self.assertEqual(bytes(one), bytes(two))

    def test_strip_signatures(self):
        key = self.get_stored_key(KEY_COMPLETE)
        KeyUtils.strip_signatures(key)

        self.assertEqual(len(key.signers), 0)
        self.assertSerializedEqual(key, self.get_stored_key(KEY_SIGNATURES_STRIPPED))

    def test_strip_uids(self):
        key = self.get_stored_key(KEY_COMPLETE)
        KeyUtils.strip_uids(key)

        self.assertEqual(len(key.userids), 0)
        self.assertSerializedEqual(key, self.get_stored_key(KEY_UIDS_STRIPPED))

    def test_strip_subkeys(self):
        key = self.get_stored_key(KEY_COMPLETE)
        KeyUtils.strip_subkeys(key)

        self.assertEqual(len(key.subkeys), 0)
        self.assertSerializedEqual(key, self.get_stored_key(KEY_SUBKEYS_STRIPPED))

    def test_strip_signatures_uids_subkeys(self):
        key = self.get_stored_key(KEY_COMPLETE)
        KeyUtils.strip_signatures_uids_subkeys(key)

        self.assertEqual(len(key.userids), 0)
        self.assertSerializedEqual(key, self.get_stored_key(KEY_FULLY_STRIPPED))

    def test_testdata_valid(self):
        original_len = len(bytes(self.get_stored_key(KEY_COMPLETE)))
        self.assertLess(len(bytes(self.get_stored_key(KEY_SIGNATURES_STRIPPED))), original_len)
        self.assertLess(len(bytes(self.get_stored_key(KEY_UIDS_STRIPPED))), original_len)
        self.assertLess(len(bytes(self.get_stored_key(KEY_SUBKEYS_STRIPPED))), original_len)
        self.assertLess(len(bytes(self.get_stored_key(KEY_FULLY_STRIPPED))), original_len)

        fully_stripped_len = len(bytes(self.get_stored_key(KEY_FULLY_STRIPPED)))
        self.assertLess(fully_stripped_len, len(bytes(self.get_stored_key(KEY_SIGNATURES_STRIPPED))))
        self.assertLess(fully_stripped_len, len(bytes(self.get_stored_key(KEY_UIDS_STRIPPED))))
        self.assertLess(fully_stripped_len, len(bytes(self.get_stored_key(KEY_SUBKEYS_STRIPPED))))