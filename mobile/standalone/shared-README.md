# shared/

Source files of the BPS node that the phone client compiles: the encrypted
overlay client, the companion protocol, keys, hashes, and the secp256k1 and
UniValue libraries. They are copied unchanged from the node's repository, so the
phone and the relay it talks to run the very same protocol code.

Do not edit them here. A change belongs in the node's repository first and is
copied over from there (`mobile/tools/export-standalone.sh` in that tree,
which also writes this folder's `files.txt`, the list of what is copied).

`version.ac` holds the node version lines the client mixes into its random
seed; nothing else reads it.
