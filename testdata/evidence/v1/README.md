# Evidence v1 synthetic test data

`minimal-raw-capture/` is a public, deterministic `NON_CANON_TEST_FIXTURE`.
Its repository Commit/Tree identities, ledger event hashes, timestamps and
payloads are synthetic. They do not identify a real repository capture, do
not contain real database content, and are not canonical product evidence.

The directory intentionally contains the exact three-file RAW_CAPTURE
inventory. Tests compare exporter output byte-for-byte with the fixture after
the exporter has independently verified the supplied synthetic stream.
