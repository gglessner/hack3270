"""
ONE-SHOT: capture output of CURRENT manipulate() before refactoring.
Run once: .venv/bin/python tests/_make_golden.py
Then never touch it again — these are the truth.

Synthetic 3270 datastreams covering each branch of manipulate()
(libhack3270.py:1869-1996):
  - L1888: SF (0x1D) + protected attr
  - L1907: SFE (0x29) with hidden 0xC0 attr pair
  - L1964: SA (0x28) with color 0x42 0xF8 black
  - L1874: telnet IAC (0xFF) — passthrough
"""
import sys, os, logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "hack3270_libs"))
os.chdir(os.path.dirname(__file__))  # so testproj.db lands here, we delete after

import libhack3270

GOLDEN = os.path.join(os.path.dirname(__file__), "golden")
os.makedirs(GOLDEN, exist_ok=True)

# Synthetic datastreams. Each is: WCC(1) + orders + IAC EOR.
# We don't need them to be *valid* 3270 — we need manipulate() to
# walk them and produce deterministic output.

# SF (0x1D) followed by attr byte 0x6C:
#   0x6C = 01101100: prot(0x20) + nondisp(0x0C) + extra bits
#   flip_bits clears prot+nondisp -> 0x44; check_hidden(0x44) is then
#   False because flip happens BEFORE the hidden check (legacy bug we
#   are preserving). So this exercises the SF flip path without HV inject.
INPUTS = {
    "sf_protected.bin":
        b"\x05" + b"\x1D\x6C" + b"\xC8\xC5\xD3\xD3\xD6" + b"\xFF\xEF",
        # WCC=05, SF, attr=0x6C (prot|nondisp|...), "HELLO" in EBCDIC, IAC EOR

    "sfe_hidden.bin":
        b"\x05" + b"\x29\x01\xC0\x4C" + b"\xE6\xD6\xD9\xD3\xC4" + b"\xFF\xEF",
        # WCC, SFE, 1 pair, type=0xC0(basic), val=0x4C (nondisp 0x0C set), "WORLD", IAC EOR
        # SFE branch checks check_hidden BEFORE flip -> triggers HV inject

    "sa_color_black.bin":
        b"\x05" + b"\x28\x42\xF8" + b"\xC4\xC1\xD9\xD2" + b"\xFF\xEF",
        # WCC, SA, 0x42(color), 0xF8(black), "DARK", IAC EOR
        # Triggers L1964-1975 SA black-color rewrite

    "telnet_iac.bin":
        b"\xFF\xFD\x28",
        # IAC DO TN3270E — manipulate() L1874 returns unchanged
}

# For each input, capture output under a specific flag combo.
# We use the "everything on" combo because it exercises the most branches.
def make_h():
    h = libhack3270.hack3270(
        server_ip="127.0.0.1", server_port=23, proxy_port=3271,
        project_name="_golden_tmp", loglevel=logging.CRITICAL,
    )
    # Enable everything (matches "everything on" attack mode)
    h.hack_on = True
    h.hack_prot = True
    h.hack_hf = True
    h.hack_rnr = True
    h.hack_ei = False
    h.hack_sf = True
    h.hack_sfe = True
    h.hack_mf = True
    h.hack_hv = True
    h.hack_color_on = True
    h.hack_color_sfe = True
    h.hack_color_mf = True
    h.hack_color_sa = True
    h.hack_color_hv = True
    return h

h = make_h()
for name, data in INPUTS.items():
    out = h.manipulate(data)
    with open(os.path.join(GOLDEN, name), "wb") as f:
        f.write(bytes(out))
    print(f"  {name}: {data.hex()} -> {bytes(out).hex()}")

# Also save the inputs themselves
for name, data in INPUTS.items():
    with open(os.path.join(GOLDEN, "in_" + name), "wb") as f:
        f.write(data)

h.sql_con.close()
os.unlink("_golden_tmp.db")
print("golden fixtures written")
