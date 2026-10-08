## SPDX-License-Identifier: BSD-3-Clause
## dsp_xlate: Shannon <-> C54x translation through neutral, high-level DSP orders.
##
##   Shannon DSP command --(ShannonCodec.decode)--> Order --(order_to_api)--> TI API RAM
##   Shannon ring word  <--(ShannonCodec.encode_result)-- Result <--(api_to_result)-- TI API RAM
##
## The middle layer (Order / Result) is neutral: it knows "search the FCCH",
## "decode the SCH", not Samsung opcodes nor TI task words.
##
## WHAT IS REAL AND WHAT IS NOT
##   * C54x side (order_to_api, api_to_result, C54xLink): real. Offsets, task ids,
##     handshake and TICK/DONE protocol come from qosmo calypso_api.h,
##     calypso_dsp_pont.h and c54x_exe/MAILBOX.md. Offsets below are BYTE offsets
##     inside the API RAM window (ARM view 0xFFD00000; shm segment 0x4000 bytes).
##   * Shannon side decode: table driven (shannon_dsp_opcodes.json). The table is
##     EMPTY by default: no GSM DSP command has been observed from the modem yet
##     (it never leaves MM_NO_RAT_MODE), so no Samsung opcode is invented here.
##     Unmapped writes are logged so the table can be filled once 2G is driven.
##   * Shannon result encoding (encode_result): SYNTHETIC. It is NOT Samsung's
##     format; it only lets the chain be exercised end to end.
##
## Opt-in: BridgeDSPPeripheral only uses this when DSP_XLATE=1.

import json
import logging
import mmap
import os
import socket
import struct
from dataclasses import dataclass, field

log = logging.getLogger("firmwire.hw.peripheral.dsp_xlate")

# ---- C54x pont constants (calypso_dsp_pont.h / calypso_api.h) ----------------
API_SHM = "/dev/shm/calypso_api_ram"
API_SHM_BYTES = 0x4000
PONT_SOCK = "/tmp/calypso_dsp.sock"
PONT_MAGIC = 0x43353458  # 'C54X'
API_WORDS = 64 * 1024 // 2  # CALYPSO_API_WORDS: what both sides announce in HELLO

PONT_HELLO, PONT_HELLO_OK, PONT_RESET, PONT_TICK, PONT_DONE, PONT_GO = 1, 2, 3, 4, 5, 6
PONT_DCCH, PONT_BYE = 7, 8
TICK_IRQ_TRAME = 1 << 16  # ARM armed the DSP frame interrupt (one shot)
DONE_API_IRQ, DONE_IDLE, DONE_INIT, DONE_RUNNING, DONE_PHASE_A = 1, 2, 4, 8, 16
_MSG = struct.Struct("=IIII")  # CalypsoPontMsg {type, a, b, c}

# ---- API RAM layout, byte offsets (calypso_api.h) ----------------------------
def W_PAGE(p):
    return 0x28 if p else 0x00


def R_PAGE(p):
    return 0x78 if p else 0x50


WP_D_TASK_D, WP_D_BURST_D, WP_D_TASK_U, WP_D_BURST_U = 0x00, 0x02, 0x04, 0x06
WP_D_TASK_MD, WP_D_TASK_RA, WP_D_FN = 0x08, 0x0E, 0x10
RP_A_SERV_DEMOD, RP_A_PM, RP_A_SCH = 0x10, 0x18, 0x1E
NDB_D_DSP_PAGE = 0x000
NDB_D_FB_DET = 0x048
NDB_D_FB_MODE = 0x04A
NDB_A_SYNC_DEMOD = 0x04C

B_GSM_PAGE, B_GSM_TASK, B_BLUD, B_SCH_CRC = 1 << 0, 1 << 1, 1 << 15, 1 << 8

PM_DSP_TASK, FB_DSP_TASK, SB_DSP_TASK, RACH_DSP_TASK, ALLC_DSP_TASK = 1, 5, 6, 10, 24

# ---- neutral layer -----------------------------------------------------------
FB, SB, CCCH, RACH, IDLE = "FB", "SB", "CCCH", "RACH", "IDLE"
KINDS = (FB, SB, CCCH, RACH, IDLE)


@dataclass
class Order:
    kind: str
    fn: int = 0
    tn: int = 0
    params: dict = field(default_factory=dict)


@dataclass
class Result:
    kind: str
    fn: int = 0
    ok: bool = False
    toa: int = 0
    pm: int = 0
    angle: int = 0
    snr: int = 0
    bsic: int = 0
    sb: int = 0


# ---- API RAM accessor --------------------------------------------------------
class ApiRam:
    """16-bit little-endian words addressed by byte offset into the API window."""

    def __init__(self, buf):
        self.buf = buf

    @classmethod
    def from_shm(cls, path=API_SHM, size=API_SHM_BYTES):
        fd = os.open(path, os.O_RDWR)
        try:
            return cls(mmap.mmap(fd, size))
        finally:
            os.close(fd)

    def rd(self, off):
        return struct.unpack_from("<H", self.buf, off)[0]

    def wr(self, off, val):
        struct.pack_into("<H", self.buf, off, val & 0xFFFF)


# ---- C54x translation (real) -------------------------------------------------
def order_to_api(api, order, page):
    """Post a neutral Order as TI task words on W page `page`."""
    base = W_PAGE(page)
    for off in (WP_D_TASK_D, WP_D_TASK_U, WP_D_TASK_MD, WP_D_TASK_RA):
        api.wr(base + off, 0)
    if order.kind == FB:
        api.wr(NDB_D_FB_DET, 0)
        api.wr(NDB_D_FB_MODE, order.params.get("mode", 0))  # 0 wide, 1 narrow search
        api.wr(base + WP_D_TASK_MD, FB_DSP_TASK)
    elif order.kind == SB:
        api.wr(base + WP_D_TASK_MD, SB_DSP_TASK)
    elif order.kind == CCCH:
        api.wr(base + WP_D_TASK_D, order.params.get("task", ALLC_DSP_TASK))
        api.wr(base + WP_D_BURST_D, order.params.get("burst", 0))
    elif order.kind == RACH:
        api.wr(base + WP_D_TASK_RA, RACH_DSP_TASK)
    elif order.kind != IDLE:
        raise ValueError("unknown order kind %r" % (order.kind,))
    api.wr(base + WP_D_FN, order.fn)
    api.wr(NDB_D_DSP_PAGE, B_GSM_TASK | (page & 1))


def api_to_result(api, kind, fn=0):
    """Read the DSP answer for an order of `kind` out of the API RAM."""
    if kind == FB:
        w = [api.rd(NDB_A_SYNC_DEMOD + 2 * i) for i in range(4)]
        return Result(FB, fn, bool(api.rd(NDB_D_FB_DET)), w[0], w[1], w[2], w[3])
    if kind == SB:
        for p in (0, 1):
            sch = [api.rd(R_PAGE(p) + RP_A_SCH + 2 * i) for i in range(5)]
            if sch[0] & B_BLUD:
                sd = [api.rd(R_PAGE(p) + RP_A_SERV_DEMOD + 2 * i) for i in range(4)]
                sb = sch[3] | (sch[4] << 16)
                return Result(SB, fn, not (sch[0] & B_SCH_CRC),
                              sd[0], sd[1], sd[2], sd[3], (sb >> 2) & 0x3F, sb)
    return Result(kind, fn, False)


class SocketTransport:
    """Client of c54x_exe --arm: SOCK_SEQPACKET lockstep, one TICK -> one DONE."""

    def __init__(self, path=PONT_SOCK, timeout=5.0):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.sock.settimeout(timeout)
        self.sock.connect(path)
        self.sock.send(_MSG.pack(PONT_HELLO, API_WORDS, PONT_MAGIC, 0))
        t, a, b, _ = _MSG.unpack(self.sock.recv(_MSG.size))
        if t != PONT_HELLO_OK or a != API_WORDS or b != PONT_MAGIC:
            raise ConnectionError("pont handshake refused: type=%d a=%#x b=%#x" % (t, a, b))

    def reset(self, dl_status=0):
        """What the ARM does on RESET_DSP release: the DSP restarts its boot ROM."""
        self.sock.send(_MSG.pack(PONT_RESET, dl_status, 0, 0))

    def tick(self, fn, b, c=0):
        self.sock.send(_MSG.pack(PONT_TICK, fn, b, c))
        while True:
            t, a, _, _ = _MSG.unpack(self.sock.recv(_MSG.size))
            if t == PONT_DONE:
                return a  # DONE_* flags

    def close(self):
        try:
            self.sock.send(_MSG.pack(PONT_BYE, 0, 0, 0))
        except OSError:
            pass
        self.sock.close()


class C54xLink:
    """Runs neutral Orders on a C54x (real, or any transport with .tick())."""

    def __init__(self, api, transport, max_frames=64):
        self.api, self.transport, self.max_frames = api, transport, max_frames
        self.page = 0
        self.fn = 0

    def boot(self, max_frames=400):
        """Reset the DSP, then tick until its first IDLE after boot (DONE_INIT)."""
        if hasattr(self.transport, "reset"):
            self.transport.reset()
        for _ in range(max_frames):
            if self.transport.tick(self.fn, 0) & DONE_INIT:
                return True
            self.fn += 1
        return False

    def run(self, order):
        """Post `order`, play frames until the DSP answers or max_frames elapse."""
        fn = order.fn or self.fn
        order = Order(order.kind, fn, order.tn, order.params)
        order_to_api(self.api, order, self.page)
        b = self.page | TICK_IRQ_TRAME  # frame interrupt is one shot per scenario
        res = Result(order.kind, fn)
        for _ in range(self.max_frames):
            self.transport.tick(fn, b)
            fn, b = fn + 1, self.page
            res = api_to_result(self.api, order.kind, order.fn)
            if res.ok or order.kind in (IDLE, CCCH, RACH):
                break
            if order.kind == SB and res.sb:  # answered, CRC bad: report it
                break
        self.fn = fn
        self.page ^= 1
        return res


# ---- Shannon translation (table driven / synthetic) --------------------------
def _int(v):
    return int(v, 0) if isinstance(v, str) else int(v)


class ShannonCodec:
    """Shannon DSP shared-struct writes -> Orders; Results -> ring words.

    Table schema (shannon_dsp_opcodes.json):
      {"version": 1, "rules": [
         {"offset": "0x60", "mask": "0xffffffff", "value": "0x...",
          "order": {"kind": "FB", "params": {}},
          "fn_mask": "0xffff", "fn_shift": 0}   # optional: fn carried in the value
      ]}
    """

    def __init__(self, rules=None):
        self.rules = []
        for r in rules or []:
            order = r["order"]
            if order["kind"] not in KINDS:
                raise ValueError("unknown order kind %r" % (order["kind"],))
            self.rules.append({
                "offset": _int(r["offset"]),
                "mask": _int(r.get("mask", 0xFFFFFFFF)),
                "value": _int(r["value"]),
                "kind": order["kind"],
                "params": dict(order.get("params", {})),
                "fn_mask": _int(r.get("fn_mask", 0)),
                "fn_shift": _int(r.get("fn_shift", 0)),
            })
        self.unmapped = {}

    @classmethod
    def from_file(cls, path):
        with open(path) as f:
            return cls(json.load(f).get("rules", []))

    def decode(self, offset, size, value):
        for r in self.rules:
            if r["offset"] == offset and (value & r["mask"]) == r["value"]:
                fn = ((value >> r["fn_shift"]) & r["fn_mask"]) if r["fn_mask"] else 0
                return Order(r["kind"], fn, 0, dict(r["params"]))
        key = (offset, value)
        self.unmapped[key] = self.unmapped.get(key, 0) + 1
        if self.unmapped[key] == 1:
            log.info("UNMAPPED DSP write off=%#x size=%d val=%#010x", offset, size, value)
        return None

    # SYNTHETIC result word, NOT Samsung's format:
    #   [31:28] kind code  [27] ok  [26:21] bsic  [20:11] snr(10b)  [10:0] pm(11b)
    _CODES = {IDLE: 0, FB: 1, SB: 2, CCCH: 3, RACH: 4}

    @classmethod
    def encode_result(cls, res):
        return ((cls._CODES[res.kind] << 28) | (int(res.ok) << 27) |
                ((res.bsic & 0x3F) << 21) | ((res.snr & 0x3FF) << 11) | (res.pm & 0x7FF))

    @classmethod
    def decode_result_word(cls, word):
        kinds = {v: k for k, v in cls._CODES.items()}
        return {"kind": kinds[(word >> 28) & 0xF], "ok": bool((word >> 27) & 1),
                "bsic": (word >> 21) & 0x3F, "snr": (word >> 11) & 0x3FF, "pm": word & 0x7FF}


# ---- the glue ----------------------------------------------------------------
class Translator:
    """Shannon write -> Order -> C54x -> Result -> Shannon ring word."""

    def __init__(self, codec, link, post_result):
        self.codec, self.link, self.post_result = codec, link, post_result
        self.pending = []

    def on_arm_write(self, offset, size, value):
        order = self.codec.decode(offset, size, value)
        if order is not None:
            self.pending.append(order)
            self.pump()

    def pump(self):
        while self.pending:
            order = self.pending.pop(0)
            if self.link is None:
                log.warning("no C54x link: dropping %s", order)
                continue
            res = self.link.run(order)
            log.info("order %s -> %s", order, res)
            self.post_result(self.codec.encode_result(res))

    @classmethod
    def from_env(cls, post_result):
        """Never raises: a missing C54x only disables forwarding."""
        here = os.path.dirname(os.path.abspath(__file__))
        table = os.environ.get("DSP_XLATE_TABLE", os.path.join(here, "shannon_dsp_opcodes.json"))
        try:
            codec = ShannonCodec.from_file(table)
        except (OSError, ValueError, KeyError) as e:
            log.warning("opcode table %s unusable (%s): no order will be decoded", table, e)
            codec = ShannonCodec()
        link = None
        try:
            api = ApiRam.from_shm()
            link = C54xLink(api, SocketTransport(os.environ.get("CALYPSO_DSP_SOCK", PONT_SOCK)),
                            int(os.environ.get("DSP_XLATE_FRAMES", "64")))
            link.boot()
        except (OSError, ConnectionError) as e:
            log.warning("C54x not reachable (%s): translator will only decode/log", e)
        return cls(codec, link, post_result)
