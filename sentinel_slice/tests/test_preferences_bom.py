"""A permissions file with a UTF-8 BOM (Notepad / PowerShell on Windows) must
load, not crash — a non-technical user should never be punished for editing
their own settings."""

from sentinel_slice.consumer.preferences import BLOCK, Preferences


def test_load_tolerates_utf8_bom(tmp_path):
    path = tmp_path / "perms.json"
    path.write_bytes(b"\xef\xbb\xbf" + b'{"cap.payment.initiate.v1": "block"}')
    prefs = Preferences.load(str(path))
    assert prefs.explicit("cap.payment.initiate.v1") == BLOCK
