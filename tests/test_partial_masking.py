from pii_detector.masking import _mask_digits_keep_tail


def test_mask_digits_keep_tail_preserves_separators():
    masked = _mask_digits_keep_tail("1234-5678-9012", keep=4)
    assert masked.endswith("9012")
    assert masked.count("-") == 2
    # First digits should be masked
    assert masked.startswith("****-**")
