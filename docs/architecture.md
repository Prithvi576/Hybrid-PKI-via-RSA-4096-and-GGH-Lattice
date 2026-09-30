# Architecture

`crypto/` is Person 1's independent signing boundary. It accepts a deterministic command envelope and returns separate RSA, GGH, and overall verification outcomes. `pki/` and `scada/` are reserved for the other team members and are not linked into the build.
