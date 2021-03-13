from pgpy import PGPUID


class GitAnonIdentity:
    pgp_uid: PGPUID
    auto_reveal: bool
    auto_reveal_encrypted: bool
    # Which identity is considered primary? The one that appears first in the config file.
    #   More than one primary identity would cause issues with unmasking.

    def __init__(self, pgp_uid: PGPUID, auto_reveal: bool, auto_reveal_encrypted: bool):
        self.pgp_uid = pgp_uid
        self.auto_reveal = auto_reveal
        self.auto_reveal_encrypted = auto_reveal_encrypted

    @classmethod
    def from_dict(cls, uid_dict: dict) -> 'GitAnonIdentity':
        name: str = uid_dict['name']
        email: str = uid_dict['email']
        comment: str = uid_dict['comment']
        auto_reveal: bool = uid_dict['auto_reveal']
        auto_reveal_encrypted: bool = uid_dict['auto_reveal_encrypted']

        uid = PGPUID.new(name, email, comment)
        return GitAnonIdentity(uid, auto_reveal, auto_reveal_encrypted)

    def to_dict(self):
        uid_dict = {
            'name': self.pgp_uid.name,
        }

        if self.pgp_uid.comment is not None:
            uid_dict['comment'] = self.pgp_uid.comment
        if self.pgp_uid.email is not None:
            uid_dict['email'] = self.pgp_uid.email

        uid_dict['auto_reveal'] = self.auto_reveal
        uid_dict['auto_reveal_encrypted'] = self.auto_reveal_encrypted

        return uid_dict
