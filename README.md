# Git-Anon: Anonymous Git with Signatures

## Project Status
This project is a usable proof of concept.  
As such it should be used mostly for experimentation and unimportant projects and likely contains multiple bugs, some of which might affect its security.

Some convenience features are not implemented yet and the storage and synchronization system might change in an incompatible way.

## Installation
```bash
pip3 install git-anon
```

## Installing from Source
```bash
python3 setup.py install
```
alternatively obtain a source- or wheel-distribution and use:
```bash
pip3 install /path/to/distribution-file
```

## Usage
Clone or initialize the repository normally (making sure to set a remote called ```origin```)

Then configure your identity:
```bash
# synchronization settings
git anon config set-enc-key "shared_secret"
# the attributes you want to share, the first one will be used as your "name" 
git anon config add-userid "John Snow" --encrypted --auto-reveal
git anon config add-userid "Member of the Nights Watch" --public --auto-reveal
git anon config add-userid "King in the North" --encrypted --no-auto-reveal
```
Consider setting up attribute certification or self certification (see the respective chapter below).

Then create your first identity:
```bash
git anon enable
git anon new-identity
```
Finally, commit, pull and push as usual.
If you think you're missing information about other identities:

```bash
git anon config set-enc-key "shared_secret" # if you know the secret and haven't provided it before
git anon update-mappings
```
If you still can't see what you're interested in, it likely wasn't shared with you.

## Certification
Any userids/attributes that you add are simply claims until they are certified by someone the relying party trusts.
This certification uses digital signatures over the attributes and their associated public keys created using certification keys.
These certification keys have to be manually imported and will be trusted to certify any attribute, that matches one of their userids.

Git-anon will use any imported certification keys, for which private keys are available to certify any matching attributes on identities it creates for you.

Keep in mind, that user ids must match exactly (including e-mails and comments).

### Self-Certification
This is the easiest and most practical certification. 
To certify that the claimed name on your anonymous identity is legitimate, you can sign it with your typical gpg key that others already trust.

This function is still rudimentary and requires you to import your unprotected private key into git-anon.

In the future this should use your regular gpg installation to request signatures, therefore supporting protected keys and keys on smartcards.
Use a separate key if you don't feel comfortable doing this with your normal key. Keep in mind that git-anon stores your private key in an unprotected format close to your git repository.

Assuming gpg finds your key using the identifier $KEY_ID:
```bash
gpg --edit-key $KEY_ID
-> passwd
-> set an empty password
-> save
-> quit
gpg --armor --export-secret-key $KEY_ID | git-anon cert trust 
```
Git-Anon will now use this key to both sign and trust (exactly) matching attributes.

### Attribute-or Role-Certification
You might want to assert attributes about yourself, without revealing your identity. 
To achieve this you can add userids that describe your membership in a group (such as "Member of the Nights Watch" above).

To then certify these assertions all (legitimate) members of this group must share access to a suitable certification key.

The easiest way of doing this is to create a certification key and sharing it directly with all members.
The more secure way would be to have one person create the key, publish it's public component and offer to certify identities for other members of the group.

First create a certification key and publish it's public half.
```bash
git anon cert gen-key --uid "Member of the Nights Watch" --output nights_watch.pub --output-secret-key nights_watch.key
```

Others can then import and trust the public half:

```bash
cat nights_watch.pub | git anon cert import
```

Then either provide the secret half to all members of the group or offer to sign their identities for them.
If the secret half of the certification key is available, git-anon will use it automatically when creating new identities.

For now the certification process for foreign identities looks like this:
```bash
# group member: create a new identity
ANONKEYID=git anon create-identity
# group member: create certificate requests
git anon cert request --keyid $ANONKEYID --uid "Member of the Nights Watch" > cert-reqeust.asc
# key holder: sign the requests (after verifying they are from legitimate members)
cat cert-request.asc | git anon cert sign --uid "Member of the Nights Watch" > cert-response.asc
# group member: import the certification
cat cert-response.asc | git anon cert import
# group member: enable the new identity
git anon use-identity $ANONKEYID   
```
Of course many identities can and should be prepared at once.

## Shared Secrets
Shared secrets must be strong enough to withstand offline brute force attacks and should therefore be generated randomly with at least 100 bits of entropy.
32 random hexadecimal characters would be a good choice.

There are no mechanisms to make brute-force more difficult, instead simply make the shared secret stronger.

## Information for Developers
### Building distributable packages
Building Python packages:
```bash
python3 setup.py test sdist bdist_wheel
```

Running system tests:
```bash
python3 setup.py bdist_wheel
docker build -t git-anon-testing .
docker run -it git-anon-testing python3 system_test.py
```

Building Debian (.deb) packages for the currently installed distribution:
```bash
sudo apt install dh-python
pip3 install stdeb
python setup.py --command-packages=stdeb.command bdist_deb
```
