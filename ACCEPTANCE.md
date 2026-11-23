# Acceptance

Use deterministic synthetic data. Cover source truncation, oversized or invalid
selections, malformed room or upload authorization, provider rejection after a
partial upload, cancellation, and finalization failure. Failed Actions must
leave history unchanged. Duplicate request IDs must reuse the same result.
Check text, image, multiple files, an empty file, an exact encryption-record
boundary, and a torrent piece spanning two files. Verify independent decryption
and exact hashes. Redact room IDs, URLs, tokens, and source paths from receipts.
Retain the first failing run. Limit retries to one per diagnosed correction.

## Verified behavior

The real Plugin RPC process and an Engine profile passed text, PNG, and
multi-file Actions, including zero bytes, a record boundary, and a piece
crossing two files. The same request ID returned the original result. The
fixture rejected malformed room IDs, unauthorized upload targets, failed
uploads after a partial transfer, and failed finalization. No failure returned
a result history ID.

The live run used a pinned independent Node recipient. It downloaded and
decrypted every file. All names, lengths, and SHA-256 fingerprints matched.
Wormhole reported 86,400 seconds for each link. The first provider probe
stopped before the upload because the probe client's retry setting of zero
also disabled the first attempt. The corrected one-attempt probe completed
the round trip. The production Go client does not use the probe client.

Rebuild receipts with `sh scripts/verify.sh` and
`UNIC_WORMHOLE_LIVE=1 sh scripts/verify.sh`. The fixtures contain synthetic
content only. No native Desktop or clipboard interaction was exercised.
