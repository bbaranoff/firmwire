## SPDX-License-Identifier: BSD-3-Clause
## BridgeDSPPeripheral: translator between the Shannon (Samsung) DSP interface
## and an external TI C54x Calypso DSP emulator (c54x_exe).
##
## STATUS: scaffold. It models the parts of the Shannon DSP shared structure that
## were reverse-engineered on CP_G973FXXS5CTD1 (SoC S5000AP); see
## memory/firmwire-c54x-dsp-bridge.md for the evidence (PCs, offsets).
##
## Decoded Shannon DSP shared struct @ dsp_base (0x47382000 on this image):
##   +0x00  sync word 0   (firmware expects 141)   checked at PC 0x40b6fccc
##   +0x04  sync word 1   (firmware expects 286)
##   +0x64  ring head (write index, u16)           reset at 0x40b6fd00
##   +0x66  ring tail (read index,  u16)
##   +0x68  ring entries (u32 each, base+0x68+idx*4) consumed at 0x40b7040e
##
## This peripheral keeps the Shannon side alive (sync + ring) and exposes a hook
## to a C54x backend. The GSM command decode (ARM->DSP) and the TI<->Samsung
## result translation are NOT done yet: they require the firmware to be driven
## into a 2G acquisition so the GSM DSP IPC (DSP_TID_*, l1x_srch_dsptch.c) is
## exercised. Those are marked TODO below.

import os
import socket
import struct

from . import PassthroughPeripheral

# Offsets inside the DSP shared structure (reverse-engineered).
OFF_SYNC0 = 0x00
OFF_SYNC1 = 0x04
OFF_RING_HEAD = 0x64   # u16 write index (DSP -> ARM producer)
OFF_RING_TAIL = 0x66   # u16 read index  (ARM consumer)
OFF_RING_BASE = 0x68   # u32 entries


class C54xBackend:
    """Client to the external c54x_exe Calypso DSP emulator.

    c54x_exe exposes TWO interfaces (see osmo-operator/pont/dsp + pont/trx.py):
      1. BSP burst input, UDP 127.0.0.1:6702. Datagram = 8-byte header
         [tn(1), fn(4, big-endian), atten(1), 0, 0] + 148 bytes (one hard bit
         0/1 per byte). This is where demodulation input (downlink bursts) go.
         In the full setup these bursts come from the osmo network via TRXD and
         pont_dsp.py; the bridge does not synthesise them.
      2. API-RAM lockstep (/dev/shm/calypso_api_ram + a frame socket) carrying
         the TI DSP API: d_task_md (5=FB,6=SB,8/9=TCH), a_sch, a_serv_demod.
         This is where DSP *tasks* are issued and *results* read back.

    The Shannon<->TI translation is the bridge's job: Shannon DSP command ->
    TI task in the API RAM; TI result (a_sch/a_serv_demod) -> Shannon ring entry.
    """

    DSP_PORT = 6702

    def __init__(self, bsp_host="127.0.0.1", bsp_port=None):
        self.bsp_host = bsp_host
        self.bsp_port = bsp_port or int(os.environ.get("CALYPSO_DSP_PORT", self.DSP_PORT))
        self.bsp = None

    def _bsp_sock(self):
        if self.bsp is None:
            self.bsp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self.bsp

    def feed_burst(self, tn, fn, bits148, atten=0):
        """Push one downlink burst into the C54x BSP (UDP 6702).

        bits148: iterable of 148 values; each sent as a byte 0/1.
        Matches pont/trx.py run_data exactly so c54x_exe accepts it unchanged.
        """
        hdr = bytes([tn & 0x07]) + struct.pack(">L", fn & 0xFFFFFFFF) + bytes([atten & 0xFF, 0, 0])
        payload = bytes(1 if b else 0 for b in bits148)
        try:
            self._bsp_sock().sendto(hdr + payload, (self.bsp_host, self.bsp_port))
            return True
        except OSError:
            return False

    # TODO: API-RAM lockstep side. Mirror what qosmo's src/pont.c does:
    #   - map /dev/shm/calypso_api_ram,
    #   - on a Shannon DSP command, write the TI task words (d_task_md etc.),
    #   - step the C54x one TDMA frame, read a_sch / a_serv_demod back.
    def api_ram_result(self):
        return None


class BridgeDSPPeripheral(PassthroughPeripheral):
    def hw_read(self, offset, size):
        if offset == OFF_SYNC0:
            self.log_read(self.dsp_sync0, size, "DSP_SYNC0")
            return self.dsp_sync0
        if offset == OFF_SYNC1:
            self.log_read(self.dsp_sync1, size, "DSP_SYNC1")
            return self.dsp_sync1
        if offset == OFF_RING_HEAD:
            self.log_read(self.ring_head, size, "RING_HEAD")
            return self.ring_head
        if offset == OFF_RING_TAIL:
            self.log_read(self.ring_tail, size, "RING_TAIL")
            return self.ring_tail
        if OFF_RING_BASE <= offset < OFF_RING_BASE + 4 * self.ring_len:
            idx = (offset - OFF_RING_BASE) // 4
            value = self.ring[idx]
            self.log_read(value, size, "RING_ENT[%d]" % idx)
            return value
        # everything else: behave like the old stub (quiet zero)
        return 0

    def hw_write(self, offset, size, value):
        if offset == OFF_RING_TAIL:
            # firmware advanced its read index; nothing to do yet
            self.ring_tail = value & 0xFFFF
            return True
        # ARM->DSP commands written into the shared struct (the ~3KB region
        # memset at boot) are decoded by dsp_xlate when DSP_XLATE=1: Shannon
        # write -> neutral Order -> C54x task -> Result -> post_result().
        if self.xlate is not None:
            self.xlate.on_arm_write(offset, size, value)
        self.log_write(value, size, "DSP_WR_off_%x" % offset)
        return True

    def post_result(self, word):
        """Publish one DSP->ARM ring entry and advance the head (producer).

        The translator calls this once a C54x result has been converted to the
        Shannon entry encoding. Left callable for when the 2G path is driven.
        """
        self.ring[self.ring_head % self.ring_len] = word & 0xFFFFFFFF
        self.ring_head = (self.ring_head + 1) & 0xFFFF
        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        if "sync" not in kwargs:
            raise ValueError("DSP sync codes required")
        self.dsp_sync0 = kwargs["sync"][0]
        self.dsp_sync1 = kwargs["sync"][1]

        self.ring_len = 30  # Ghidra: modulo-30 circular MEASUREMENT buffer (averaging consumer), not the task channel
        self.ring = [0] * self.ring_len
        self.ring_head = 0
        self.ring_tail = 0

        # Opt-in Shannon <-> C54x order translation (see dsp_xlate.py).
        self.xlate = None
        if os.environ.get("DSP_XLATE") == "1":
            from .dsp_xlate import Translator
            self.xlate = Translator.from_env(self.post_result)

        self.backend = C54xBackend(
            os.environ.get("CALYPSO_DSP_SOCK", "/tmp/calypso_dsp.sock")
        )

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
