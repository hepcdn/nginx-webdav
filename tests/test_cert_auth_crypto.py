"""
Tests for the lua-resty-openssl crypto port in cert_auth.lua (PR #79,
review issue 1).

The rest of the suite's certificate tests (test_cert_bound_gossip.py)
exercise only the openssl CLI and never touch the Lua code. These tests
run the real cert_auth.lua inside the built image and cross-check its
output against the openssl CLI, proving the ported signing,
verification and fingerprint semantics are byte-compatible:

    cert_auth.sign(data)        ==  openssl dgst -sha256 -sign key.pem
    cert_auth.verify(...)       ==  openssl dgst -sha256 -verify
    cert_auth.get_fingerprint() ==  openssl x509 -noout -fingerprint -sha256

The module requires "ngx" for logging and hex/base64 helpers; a minimal
stub is installed in the test driver before requiring cert_auth from the
image's /etc/nginx/lua (the shipped module, not a copy).
"""

import base64
import os
import subprocess

import pytest

# Lua driver: installs an ngx stub, loads the real cert_auth.lua from
# /work/lua, and exercises load_cert/get_fingerprint/get_subject/sign/
# verify against files staged in /work by the test.
DRIVER_LUA = r"""
-- minimal ngx stub for the test driver
local function tofile_b64(data, decode)
  local tmp = "/work/.b64tmp"
  local f = assert(io.open(tmp, "wb"))
  f:write(data)
  f:close()
  local cmd = decode and ("openssl base64 -d -A < " .. tmp)
                     or ("openssl base64 -A < " .. tmp)
  local p = assert(io.popen(cmd))
  local s = p:read("*a")
  p:close()
  os.remove(tmp)
  return s
end
local ngx_stub = {
  ERR = 1,
  WARN = 2,
  log = function(lv, ...)
    local t = {}
    for i = 1, select("#", ...) do t[i] = tostring(select(i, ...)) end
    io.stderr:write(table.concat(t, " "), "\n")
  end,
  encode_hex = function(s)
    return (s:gsub(".", function(c)
      return string.format("%02x", c:byte())
    end))
  end,
  encode_base64 = function(data) return tofile_b64(data, false) end,
  decode_base64 = function(data) return tofile_b64(data, true) end,
}
package.preload["ngx"] = function() return ngx_stub end

-- the module under test is the one shipped in the image
package.path = "/etc/nginx/lua/?.lua;" .. package.path
local cert_auth = require("cert_auth")
cert_auth.cert_path = "/work/hostcert.pem"
cert_auth.key_path = "/work/hostkey.pem"

assert(cert_auth.load_cert(), "load_cert failed")
print("FINGERPRINT=" .. cert_auth.get_fingerprint())
print("SUBJECT=" .. cert_auth.get_subject())

local msg = "gossip-interop-message"
local sig_b64 = cert_auth.sign(msg)
assert(sig_b64, "sign failed")
local raw = ngx_stub.decode_base64(sig_b64)
local f = assert(io.open("/work/sig.bin", "wb"))
f:write(raw)
f:close()
print("LUA_SIGN_LEN=" .. #raw)

-- verify a signature produced by the openssl CLI (staged by the test)
local clif = assert(io.open("/work/cli_sig.b64"))
local cli_sig = clif:read("*a")
clif:close()
local certf = assert(io.open("/work/hostcert.pem"))
local cert_pem = certf:read("*a")
certf:close()
print("VERIFY_CLI=" .. tostring(cert_auth.verify(msg, cli_sig, cert_pem)))
print("VERIFY_TAMPERED="
    .. tostring(cert_auth.verify(msg .. "x", cli_sig, cert_pem)))
print("VERIFY_BADSIG="
    .. tostring(cert_auth.verify(msg, "AAAA", cert_pem)))
print("DRIVER_DONE")
"""


@pytest.fixture
def interop_env(tmp_path):
    """Stage a host key/cert plus a CLI-generated signature in /work."""
    cert = tmp_path / "hostcert.pem"
    key = tmp_path / "hostkey.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "30",
         "-subj", "/C=US/O=Mock Host/CN=node1.example.com"],
        capture_output=True, check=True)

    msg = b"gossip-interop-message"
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(key),
         "-out", str(tmp_path / "cli_sig.bin")],
        input=msg, check=True)
    cli_sig_b64 = base64.b64encode(
        (tmp_path / "cli_sig.bin").read_bytes()).decode()
    (tmp_path / "cli_sig.b64").write_text(cli_sig_b64)

    (tmp_path / "driver.lua").write_text(DRIVER_LUA)
    return tmp_path


def _run_driver(workdir):
    result = subprocess.run(
        ["podman", "run", "--rm",
         "-e", "LD_PRELOAD=/lib64/libcrypto.so.3",
         "-v", f"{workdir}:/work",
         "nginx-webdav",
         "/usr/local/openresty/luajit/bin/luajit", "/work/driver.lua"],
        capture_output=True, text=True)
    if result.returncode != 0:
        raise AssertionError(
            f"driver exited {result.returncode}\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}")
    return result


def test_cert_auth_fingerprint_matches_openssl(build_container, interop_env):
    out = _run_driver(interop_env)
    lines = dict(
        l.split("=", 1) for l in out.stdout.splitlines() if "=" in l)
    assert lines.get("FINGERPRINT", "").startswith("sha256:")

    cli_fp = subprocess.check_output(
        ["openssl", "x509", "-in", str(interop_env / "hostcert.pem"),
         "-noout", "-fingerprint", "-sha256"], text=True).strip()
    expected = "sha256:" + cli_fp.split("=")[1].replace(":", "").lower()
    assert lines["FINGERPRINT"] == expected

    assert "node1.example.com" in lines.get("SUBJECT", "")


def test_cert_auth_lua_and_cli_signatures_interoperate(
        build_container, interop_env):
    out = _run_driver(interop_env)
    lines = dict(
        l.split("=", 1) for l in out.stdout.splitlines() if "=" in l)
    assert "DRIVER_DONE" in out.stdout

    # Lua's signature must be a real RSA-2048 signature and must verify
    # with the openssl CLI against the same message.
    sig = (interop_env / "sig.bin").read_bytes()
    assert len(sig) == 256, f"LUA_SIGN_LEN={lines.get('LUA_SIGN_LEN')}"
    msg_file = interop_env / "msg.txt"
    msg_file.write_bytes(b"gossip-interop-message")
    # openssl 3.x -verify wants a key file, not a certificate
    pub_file = interop_env / "hostpub.pem"
    subprocess.run(
        ["openssl", "x509", "-in", str(interop_env / "hostcert.pem"),
         "-pubkey", "-noout", "-out", str(pub_file)],
        check=True, capture_output=True)
    result = subprocess.run(
        ["openssl", "dgst", "-sha256",
         "-verify", str(pub_file),
         "-signature", str(interop_env / "sig.bin"),
         str(msg_file)],
        capture_output=True, text=True)
    assert "Verified OK" in result.stdout, result.stdout + result.stderr

    # And the Lua side must verify a CLI-produced signature, reject
    # tampered data, and reject a malformed signature.
    assert lines["VERIFY_CLI"] == "true"
    assert lines["VERIFY_TAMPERED"] == "false"
    assert lines["VERIFY_BADSIG"] == "false"
