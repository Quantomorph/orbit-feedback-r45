# Public snapshot provenance

Prepared: 2026-10-13. Release type: feedback-only.

Source commit: `6f70ae19cc9df4a9927d8e505173089153eddac4`.
Source tree: `515fd35c03ea85231e753557f6b3a2d609f866db`.

The export includes only `orbit/`, `tests/`, and `RUN_TESTS.sh`, preserved byte-for-byte. [SOURCE_FILES_SHA256.csv](SOURCE_FILES_SHA256.csv) lists the SHA-256 and Git blob ID of each of those 70 files, checked against the source commit. Every other file (README, `CONTRIBUTING.md`, `LICENSING.md`, `.gitignore`, and the rest of `docs/`) is newly written for this release and is not a historical acceptance artifact.

[TEST_RUN_LINUX_20261013.txt](TEST_RUN_LINUX_20261013.txt) is the unedited output of `RUN_TESTS.sh` from an independent rerun of these source bytes on 2026-10-13 (SHA-256 `8f575a19e6176924db0838a6f92dcc0bc12e461590b3af6ea17886843c54d1d5`).

The private repository's history is preserved separately. This release has no commit author/tagger metadata, private consultation transcript, raw authorization record, operator-supplied credential material, or server installation configuration. Credential-pattern scanning found nothing; that is not a guarantee, and further review is welcome.

Historical repository construction dates must not automatically be read as the dates of the original engineering work. The source checkpoint and its documentary acceptance were reconciled against preserved bundles and hash-verified records. Tags were unsigned; object equality establishes integrity relative to that custody chain, not a cryptographic owner signature.

This export is not the latest private working state. No bridge acceptance, exchange-integration acceptance, or deployment approval is implied by it.
