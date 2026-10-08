from app.engine.mask import Masker


def test_mask_keeps_timestamps_and_masks_addresses():
    m = Masker(["ACME LTDA"])
    out = m.mask('200.243.39.102 - u [08/Oct/2026:01:00:37 -0300] 2804:18:70ac:11bb:1899:aa87:b571:9fef fe80::1 a@b.com.br ACME LTDA '
                 '10.1.2.3 41eb30d2-db7c-41db-a187-e11eda8ea728 S-1-5-21-111-222-333-1001')
    assert "08/Oct/2026:01:00:37" in out
    for leaked in ("200.243.39.102", "2804:18", "fe80::1", "a@b.com.br", "ACME", "10.1.2.3", "41eb30d2", "S-1-5-21-111"):
        assert leaked not in out
    assert m.mask("200.243.39.102") == "198.18.0.1"  # consistente
