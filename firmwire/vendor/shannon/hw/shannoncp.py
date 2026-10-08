## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import os
import sys
import mmap
import struct
import logging
import binascii

from avatar2 import *

from . import FirmWirePeripheral
from firmwire.hw.fifo import CircularFIFO

log = logging.getLogger(__name__)

# TX and RX are from perspective of AP
# Same for head/tail and write/read
# e.g. TX means AP2CP
memory_map = {
    "magic": 0x00,
    "access": 0x04,
    "fmt_tx_head": 0x08,
    "fmt_tx_tail": 0x0C,
    "fmt_rx_head": 0x10,
    "fmt_rx_tail": 0x14,
    "raw_tx_head": 0x18,
    "raw_tx_tail": 0x1C,
    "raw_rx_head": 0x20,
    "raw_rx_tail": 0x24,
    # "reserved"    : 0x28, # 4056 bytes for padding to next page (0x1000)
}

memory_map_inv = dict([[v, k] for k, v in memory_map.items()])

# BOOT magic the AP expects to read first (big-endian "BOOT" -> 0x424F4F54)
SHM_MAGIC_BOOT = struct.unpack(">I", b"BOOT")[0]
SHM_MAGIC_ACTIVE = 0xAA

# Layout of the four FIFOs inside the SHM region (offset, size), identical to
# the in-Python model below. In shared-backing mode these live in the mmap'd
# file so an external AP (pmOS kernel via ivshmem) sees the exact same bytes.
FIFO_LAYOUT = {
    "fmt_tx_buff": (0x1000, 0x1000),     # AP -> CP  (CP recv)
    "fmt_rx_buff": (0x2000, 0x1000),     # CP -> AP  (CP send)
    "raw_tx_buff": (0x3000, 0x1FD000),   # AP -> CP  (CP recv)
    "raw_rx_buff": (0x200000, 0x200000), # CP -> AP  (CP send)
}


# exact map to drivers/misc/modem_v1/link_device_memory.h
# struct __packed shmem_4mb_phys_map
class SHMPeripheral(FirmWirePeripheral):
    """Shannon AP<->CP shared memory.

    Two modes:

    * Default (upstream): the region is modelled in Python. The four FIFOs and
      the header pointers live in CircularFIFO objects; FirmWire plays the role
      of the AP (it fakes the BOOT handshake and drains/queues packets).

    * Shared backing (env FIRMWIRE_CP_SHM=<path>): the whole region is mmap'd
      onto a file (e.g. /dev/shm/firmwire_cp_shm). Every MMIO access from the
      modem is served straight from the file, so a second process -- e.g. a
      pmOS QEMU mapping the same file over an ivshmem BAR -- shares identical
      memory. Header pointers (head/tail) and FIFO payloads are then maintained
      cooperatively by the modem (CP side) and the external AP, like real
      silicon.

      With FIRMWIRE_CP_SHM_EXTERNAL_AP=1 FirmWire stops faking the AP side of
      the boot handshake (magic flip / access bit), leaving it to the real AP.
    """

    # -- shared-backing helpers -------------------------------------------
    def _open_backing(self):
        fd = os.open(self._shm_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.ftruncate(fd, self._shm_size)
        self._shm_fd = fd
        self._shm_mmap = mmap.mmap(fd, self._shm_size)

    def _b(self):
        if self._shm_mmap is None:
            self._open_backing()
        return self._shm_mmap

    def _read_int(self, offset, size):
        b = self._b()
        return int.from_bytes(b[offset : offset + size], "little")

    def _write_int(self, offset, size, value):
        b = self._b()
        b[offset : offset + size] = int(value & ((1 << (size * 8)) - 1)).to_bytes(
            size, "little"
        )

    def _init_shared_header(self):
        # FirmWire owns CP boot, so lay down a fresh header.
        self._write_int(0x00, 4, SHM_MAGIC_BOOT)
        self._write_int(0x04, 4, 0)  # access
        for off in range(0x08, 0x28, 4):  # all head/tail pointers
            self._write_int(off, 4, 0)

    def _fifo_name(self, offset):
        for name, (start, sz) in FIFO_LAYOUT.items():
            if start <= offset < start + sz:
                return "%s[%x]" % (name, offset - start)
        return None

    def _shared_queue(self, region_name, head_off, pkt):
        """Mirror CircularFIFO.queue() into the mmap: append pkt at the region's
        producer head and advance the head pointer in the SHM header."""
        start, sz = FIFO_LAYOUT[region_name]
        head = self._read_int(head_off, 4)
        b = self._b()
        for i, c in enumerate(pkt):
            b[start + ((head + i) % sz)] = c
        head = (head + len(pkt)) % sz
        self._write_int(head_off, 4, head)
        self.log.debug(
            "%s[QUEUE] %s head=%#x", region_name, binascii.hexlify(pkt).decode(), head
        )

    # -- MMIO -------------------------------------------------------------
    def hw_read(self, offset, size):
        if self.shared:
            if offset == 0x0:
                value = self._read_int(0x0, size)
                # Fake the AP side of the handshake unless a real AP drives it.
                if not self.external_ap:
                    self._write_int(0x0, 4, SHM_MAGIC_ACTIVE)
                    self._write_int(0x4, 4, 1)
                self.log_read(value, size, "magic")
                return value

            value = self._read_int(offset, size)
            offset_name = memory_map_inv.get(offset)
            if offset_name is None:
                offset_name = self._fifo_name(offset) or ("%x" % offset)
            self.log_read(value, size, offset_name)
            return value

        offset_name = None
        if offset == 0x0:
            value = self.magic
            self.magic = 0xAA
            self.access = 1
        elif offset == 0x4:
            value = self.access

        elif offset == 0x8:
            value = self.fmt_tx_buff.head
        elif offset == 0xC:
            value = self.fmt_tx_buff.tail
        elif offset == 0x10:
            value = self.fmt_rx_buff.head
        elif offset == 0x14:
            value = self.fmt_rx_buff.tail

        elif offset == 0x18:
            value = self.raw_tx_buff.head
        elif offset == 0x1C:
            value = self.raw_tx_buff.tail
        elif offset == 0x20:
            value = self.raw_rx_buff.head
        elif offset == 0x24:
            value = self.raw_rx_buff.tail

        else:
            found = False
            for i, fifo in enumerate(
                [self.fmt_tx_buff, self.fmt_rx_buff, self.raw_tx_buff, self.raw_rx_buff]
            ):
                if fifo.within(offset):
                    found = True
                    fo = fifo.rebase(offset)
                    value = fifo.read_raw(fo, size)
                    offset_name = "%s_READ[%x]" % (fifo.name, fo)
                    break

            if not found and offset + size <= len(self.reserved):
                # Non-FIFO header/padding area (0x28..): keep what the AP wrote.
                value = int.from_bytes(self.reserved[offset : offset + size], "little")
                offset_name = "RSV[%x]" % offset
                found = True
            if not found:
                value = 0
                offset_name = "%x" % offset

        if offset_name is None:
            if offset in memory_map_inv:
                offset_name = memory_map_inv[offset]
            else:
                offset_name = "unknown"

        self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):
        if self.shared:
            self._write_int(offset, size, value)
            offset_name = memory_map_inv.get(offset)
            if offset_name is None:
                offset_name = self._fifo_name(offset) or ("%x" % offset)
            self.log_write(value, size, offset_name)
            return True

        offset_name = None
        if offset == 0x0:
            self.magic = value
        elif offset == 0x4:
            self.access = value

        elif offset == 0x8:
            self.fmt_tx_buff.head = value
        elif offset == 0xC:
            self.fmt_tx_buff.tail = value
        elif offset == 0x10:
            self.fmt_rx_buff.head = value
            # TODO: dequeue elsewhere for handling
            self.fmt_rx_buff.dequeue()
        elif offset == 0x14:
            self.fmt_rx_buff.tail = value

        elif offset == 0x18:
            self.raw_tx_buff.head = value
        elif offset == 0x1C:
            self.raw_tx_buff.tail = value
        elif offset == 0x20:
            self.raw_rx_buff.head = value
            # TODO: dequeue elsewhere for handling
            self.raw_rx_buff.dequeue()
        elif offset == 0x24:
            self.raw_rx_buff.tail = value

        else:
            found = False
            for i, fifo in enumerate(
                [self.fmt_tx_buff, self.fmt_rx_buff, self.raw_tx_buff, self.raw_rx_buff]
            ):
                if fifo.within(offset):
                    found = True
                    fo = fifo.rebase(offset)
                    fifo.write_raw(fo, size, value)
                    offset_name = "%s_WRITE[%x]" % (fifo.name, fo)
                    break

            if not found and offset + size <= len(self.reserved):
                # Non-FIFO header/padding area (0x28..): the AP may write it.
                self.reserved[offset : offset + size] = (
                    int(value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
                )
                offset_name = "RSV[%x]" % offset
                found = True
            if not found:
                value = 0
                offset_name = "%x" % offset

        if offset_name is None:
            if offset in memory_map_inv:
                offset_name = memory_map_inv[offset]
            else:
                offset_name = "unknown"

        self.log_write(value, size, offset_name)

        return True

    def send_raw_packet(self, pkt):
        if self.shared:
            # When a real AP (pmOS) is attached it drives the raw_tx channel
            # itself over ivshmem; FirmWire must not also play the AP.
            if self.external_ap:
                self.log.debug("ignoring send_raw_packet (external AP drives boot)")
                return
            self._shared_queue("raw_tx_buff", memory_map["raw_tx_head"], pkt)
            return
        self.raw_tx_buff.queue(pkt)

    def __getstate__(self):
        state = super().__getstate__()
        # mmap / fd are process-local: reopened lazily from _shm_path after restore
        state["_shm_mmap"] = None
        state["_shm_fd"] = None
        return state

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self._shm_path = os.environ.get("FIRMWIRE_CP_SHM")
        self.shared = self._shm_path is not None
        self.external_ap = os.environ.get("FIRMWIRE_CP_SHM_EXTERNAL_AP") == "1"
        self._shm_size = size
        self._shm_mmap = None
        self._shm_fd = None

        if self.shared:
            self._open_backing()
            self._init_shared_header()
            self.log.info(
                "SHM backed by %s (%#x bytes)%s",
                self._shm_path,
                self._shm_size,
                " [external AP]" if self.external_ap else "",
            )
        else:
            self.access = 0
            self.magic = SHM_MAGIC_BOOT  # Or mode DUMP
            # Backing store for the non-FIFO part of the region (0x28..size)
            self.reserved = bytearray(size)

            # TX/RX relative to AP
            self.fmt_tx_buff = CircularFIFO("fmt_tx_buff", 0x1000, 0x1000)  # CP recv
            self.fmt_rx_buff = CircularFIFO("fmt_rx_buff", 0x2000, 0x1000)  # CP send
            self.raw_tx_buff = CircularFIFO("raw_tx_buff", 0x3000, 0x1FD000)  # CP recv
            self.raw_rx_buff = CircularFIFO(
                "raw_rx_buff", 0x200000, 0x200000
            )  # CP send

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
