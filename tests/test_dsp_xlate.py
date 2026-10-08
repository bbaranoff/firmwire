"""Tests for firmwire.vendor.shannon.hw.dsp_xlate (no emulator, no real DSP needed).

dsp_xlate is loaded straight from its file: importing the firmwire package would
pull in avatar2/qemu, which these tests do not need.
"""
import importlib.util
import json
import tempfile
from pathlib import Path

_SRC = Path(__file__).parent.parent / "firmwire/vendor/shannon/hw/dsp_xlate.py"
_spec = importlib.util.spec_from_file_location("dsp_xlate", _SRC)
x = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(x)


class FakeDsp:
    """Stands in for c54x_exe: answers FB after `fb_after` frames, SB at once."""

    def __init__(self, api, fb_after=3, sb_crc_ok=True):
        self.api, self.fb_after, self.sb_crc_ok = api, fb_after, sb_crc_ok
        self.ticks = 0
        self.fb_ticks = 0
        self.log = []

    def tick(self, fn, b, c=0):
        self.ticks += 1
        self.log.append((fn, b))
        page = self.api.rd(x.NDB_D_DSP_PAGE) & 1
        md = self.api.rd(x.W_PAGE(page) + x.WP_D_TASK_MD)
        if md == x.FB_DSP_TASK:
            self.fb_ticks += 1
            if self.fb_ticks >= self.fb_after:
                self.api.wr(x.NDB_D_FB_DET, 1)
                for i, v in enumerate((23, 700, 5, 0x4000)):  # TOA PM ANGLE SNR
                    self.api.wr(x.NDB_A_SYNC_DEMOD + 2 * i, v)
        elif md == x.SB_DSP_TASK:
            sb = (0x2A << 2) | 0x1000  # BSIC 0x2a
            status = x.B_BLUD | (0 if self.sb_crc_ok else x.B_SCH_CRC)
            base = x.R_PAGE(0) + x.RP_A_SCH
            for i, v in enumerate((status, 0, 0, sb & 0xFFFF, sb >> 16)):
                self.api.wr(base + 2 * i, v)
            for i, v in enumerate((23, 700, 5, 0x4000)):
                self.api.wr(x.R_PAGE(0) + x.RP_A_SERV_DEMOD + 2 * i, v)
        return x.DONE_IDLE | x.DONE_API_IRQ


def make_link(**kw):
    api = x.ApiRam(bytearray(x.API_SHM_BYTES))
    dsp = FakeDsp(api, **kw)
    return api, dsp, x.C54xLink(api, dsp, max_frames=16)


def test_order_to_api_words():
    api = x.ApiRam(bytearray(x.API_SHM_BYTES))
    x.order_to_api(api, x.Order(x.FB, fn=1234, params={"mode": 1}), page=1)
    assert api.rd(x.W_PAGE(1) + x.WP_D_TASK_MD) == 5
    assert api.rd(x.W_PAGE(1) + x.WP_D_FN) == 1234
    assert api.rd(x.NDB_D_FB_MODE) == 1
    assert api.rd(x.NDB_D_DSP_PAGE) == (x.B_GSM_TASK | 1)
    x.order_to_api(api, x.Order(x.SB, fn=7), page=0)
    assert api.rd(x.W_PAGE(0) + x.WP_D_TASK_MD) == 6
    x.order_to_api(api, x.Order(x.IDLE), page=0)
    assert api.rd(x.W_PAGE(0) + x.WP_D_TASK_MD) == 0


def test_fb_search_runs_until_detection():
    api, dsp, link = make_link(fb_after=3)
    res = link.run(x.Order(x.FB, fn=100))
    assert res.ok and (res.toa, res.pm, res.angle, res.snr) == (23, 700, 5, 0x4000)
    assert dsp.ticks == 3
    assert dsp.log[0][1] & x.TICK_IRQ_TRAME          # frame IRQ armed once...
    assert not dsp.log[1][1] & x.TICK_IRQ_TRAME      # ...and only once
    assert [f for f, _ in dsp.log] == [100, 101, 102]


def test_fb_not_found_gives_up():
    api, dsp, link = make_link(fb_after=10**6)
    res = link.run(x.Order(x.FB, fn=0))
    assert not res.ok and dsp.ticks == 16


def test_sb_bsic_and_crc():
    api, dsp, link = make_link()
    res = link.run(x.Order(x.SB, fn=50))
    assert res.ok and res.bsic == 0x2A
    api, dsp, link = make_link(sb_crc_ok=False)
    res = link.run(x.Order(x.SB, fn=50))
    assert not res.ok and res.bsic == 0x2A  # answered, CRC error reported


def test_page_flips_between_orders():
    api, dsp, link = make_link()
    link.run(x.Order(x.SB, fn=1))
    link.run(x.Order(x.SB, fn=2))
    assert [b & 1 for _, b in dsp.log if b & x.TICK_IRQ_TRAME] == [0, 1]


def test_result_word_roundtrip():
    res = x.Result(x.SB, 9, True, 23, 700, 5, 0x155, 0x2A)
    d = x.ShannonCodec.decode_result_word(x.ShannonCodec.encode_result(res))
    assert d == {"kind": "SB", "ok": True, "bsic": 0x2A, "snr": 0x155, "pm": 700}


def test_codec_table_and_unmapped():
    codec = x.ShannonCodec([{"offset": "0x60", "mask": "0xff000000", "value": "0x01000000",
                             "order": {"kind": "FB"}, "fn_mask": "0xffff", "fn_shift": 0}])
    o = codec.decode(0x60, 4, 0x0100ABCD)
    assert o.kind == x.FB and o.fn == 0xABCD
    assert codec.decode(0x60, 4, 0x02000000) is None
    assert codec.decode(0x64, 4, 1) is None
    assert codec.unmapped[(0x64, 1)] == 1


def test_empty_default_table_maps_nothing():
    path = Path(__file__).parent.parent / "firmwire/vendor/shannon/hw/shannon_dsp_opcodes.json"
    codec = x.ShannonCodec.from_file(path)
    assert codec.rules == [] and codec.decode(0x60, 4, 1) is None


def test_translator_end_to_end():
    api, dsp, link = make_link(fb_after=2)
    codec = x.ShannonCodec([{"offset": "0x5c", "value": "0xf0", "order": {"kind": "FB"}}])
    posted = []
    t = x.Translator(codec, link, posted.append)
    t.on_arm_write(0x5C, 4, 0xF0)     # a Shannon-side write -> FB search -> ring word
    assert len(posted) == 1
    d = x.ShannonCodec.decode_result_word(posted[0])
    assert d["kind"] == "FB" and d["ok"] and d["pm"] == 700
    t.on_arm_write(0x5C, 4, 0x11)     # unmapped: nothing posted
    assert len(posted) == 1


def test_translator_without_link_does_not_raise():
    codec = x.ShannonCodec([{"offset": "0x5c", "value": "0xf0", "order": {"kind": "FB"}}])
    posted = []
    x.Translator(codec, None, posted.append).on_arm_write(0x5C, 4, 0xF0)
    assert posted == []


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
