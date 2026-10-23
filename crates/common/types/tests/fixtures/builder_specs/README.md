# builder-specs examples

Copied unchanged from `ethereum/builder-specs` at `fce6446` (2026-10-20),
`examples/<fork>/`. CC0 1.0, like the rest of that repository.

Each `.json` is an API response body: the object sits under `value`, and the
bid adds a `{version, data}` envelope. Each `.ssz` is the bare object.

The registration example lives under `bellatrix/` upstream because
`ValidatorRegistrationV1` is not fork-versioned.
