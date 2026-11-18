# builder-specs examples

Copied unchanged from `ethereum/builder-specs` at
`fce64468a81a87892d7cb9b4858272bb3d010e50` (2026-10-20), `examples/<fork>/`.
CC0 1.0, like the rest of that repository.

These are the OpenAPI examples the spec's endpoints cite. Each `.json` holds
its object under `value`, OpenAPI's example wrapper, which is never sent on
the wire. Each `.ssz` is the same object's SSZ encoding.

| Example | What it is |
|---|---|
| `bellatrix/signed_validator_registrations` | `registerValidator` request body: a list of registrations |
| `fulu/signed_builder_bid` | `getHeader` response; the JSON keeps the real `{version, data}` envelope, the SSZ is the bare `SignedBuilderBid` |
| `fulu/signed_blinded_beacon_block` | `submitBlindedBlockV2` request body |

The registration example lives under `bellatrix/` upstream because
`ValidatorRegistrationV1` is not fork-versioned.
