"""
Phase 3 attack modules.

Each attack is a self-contained module that takes a daemon (real ProxyDaemon
or test FakeDaemon) and registers observers/intercepts. Modules:

  tn3270_v2     - clean-room 3270 datastream parser (replaces legacy regex)
  esm_finger    - passive ESM (RACF/ACF2/TSS) fingerprinter
  lu_spoof      - LU-name spoofer (TN3270E CONNECT negotiation)
  query_reply   - Structured Field Query Reply builder
  indfile       - IND$FILE transfer detector
  state_fuzz    - record/analyze/replay AID-key state fuzzer
"""
