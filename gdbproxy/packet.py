"""RSP packet parsing and validation."""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Iterator

from .constants import (
    ACK,
    ESCAPE,
    ESCAPE_XOR,
    INTERRUPT,
    NACK,
    NOTIFICATION_START,
    PACKET_END,
    PACKET_START,
)


class PacketType(Enum):
    ACK = auto()
    NACK = auto()
    INTERRUPT = auto()
    PACKET = auto()
    NOTIFICATION = auto()


@dataclass
class Packet:
    type: PacketType
    data: bytes = b""
    checksum: int = 0
    raw: bytes = b""
    valid_checksum: bool = True

    @property
    def data_str(self) -> str:
        """Return data as string, handling binary data gracefully."""
        try:
            return self.data.decode("latin-1")
        except UnicodeDecodeError:
            return self.data.hex()


def compute_checksum(data: bytes) -> int:
    """Compute RSP checksum (sum of bytes mod 256)."""
    return sum(data) & 0xFF


def unescape(data: bytes) -> bytes:
    """Unescape RSP data (} followed by byte XOR 0x20)."""
    result = bytearray()
    i = 0
    while i < len(data):
        if data[i] == ESCAPE and i + 1 < len(data):
            result.append(data[i + 1] ^ ESCAPE_XOR)
            i += 2
        else:
            result.append(data[i])
            i += 1
    return bytes(result)


class ParserState(Enum):
    IDLE = auto()
    IN_PACKET = auto()
    CHECKSUM_1 = auto()
    CHECKSUM_2 = auto()


class PacketParser:
    """State machine for extracting RSP packets from a byte stream."""

    def __init__(self):
        self._state = ParserState.IDLE
        self._buffer = bytearray()
        self._packet_start = 0
        self._checksum_chars = bytearray()
        self._is_notification = False
        self._raw_buffer = bytearray()

    def feed(self, data: bytes) -> Iterator[Packet]:
        """Feed bytes into the parser and yield complete packets."""
        for byte in data:
            packet = self._process_byte(byte)
            if packet is not None:
                yield packet

    def _process_byte(self, byte: int) -> Packet | None:
        if self._state == ParserState.IDLE:
            return self._handle_idle(byte)
        elif self._state == ParserState.IN_PACKET:
            return self._handle_in_packet(byte)
        elif self._state == ParserState.CHECKSUM_1:
            return self._handle_checksum_1(byte)
        elif self._state == ParserState.CHECKSUM_2:
            return self._handle_checksum_2(byte)
        return None

    def _handle_idle(self, byte: int) -> Packet | None:
        if byte == ACK:
            return Packet(PacketType.ACK, raw=bytes([byte]))
        elif byte == NACK:
            return Packet(PacketType.NACK, raw=bytes([byte]))
        elif byte == INTERRUPT:
            return Packet(PacketType.INTERRUPT, raw=bytes([byte]))
        elif byte == PACKET_START:
            self._state = ParserState.IN_PACKET
            self._buffer.clear()
            self._raw_buffer = bytearray([byte])
            self._is_notification = False
        elif byte == NOTIFICATION_START:
            self._state = ParserState.IN_PACKET
            self._buffer.clear()
            self._raw_buffer = bytearray([byte])
            self._is_notification = True
        return None

    def _handle_in_packet(self, byte: int) -> Packet | None:
        self._raw_buffer.append(byte)
        if byte == PACKET_END:
            self._state = ParserState.CHECKSUM_1
            self._checksum_chars.clear()
        else:
            self._buffer.append(byte)
        return None

    def _handle_checksum_1(self, byte: int) -> Packet | None:
        self._raw_buffer.append(byte)
        self._checksum_chars.append(byte)
        self._state = ParserState.CHECKSUM_2
        return None

    def _handle_checksum_2(self, byte: int) -> Packet | None:
        self._raw_buffer.append(byte)
        self._checksum_chars.append(byte)
        self._state = ParserState.IDLE

        try:
            checksum = int(self._checksum_chars.decode("ascii"), 16)
        except ValueError:
            checksum = 0

        data = bytes(self._buffer)
        computed = compute_checksum(data)
        valid = computed == checksum

        packet_type = (
            PacketType.NOTIFICATION if self._is_notification else PacketType.PACKET
        )

        return Packet(
            type=packet_type,
            data=data,
            checksum=checksum,
            raw=bytes(self._raw_buffer),
            valid_checksum=valid,
        )

    def reset(self):
        """Reset parser state."""
        self._state = ParserState.IDLE
        self._buffer.clear()
        self._checksum_chars.clear()
        self._raw_buffer.clear()
