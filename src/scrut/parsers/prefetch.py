"""Prefetch parser for Scrut DFIR CLI.

Custom implementation that parses Windows Prefetch files without external dependencies.
Supports versions 17 (XP), 23 (Vista/7), 26 (8/8.1), and 30 (Win10+).
"""

import struct
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from scrut.models.record import ParsedRecord
from scrut.parsers.base import BaseParser, ParserRegistry

PARSER_VERSION = "0.1.0"

# Prefetch signatures
PREFETCH_SIGNATURE_SCCA = b"SCCA"  # Standard prefetch
PREFETCH_SIGNATURE_MAM = b"MAM\x04"  # Compressed (Win10+)

# Prefetch versions
VERSION_XP = 17  # Windows XP, 2003
VERSION_VISTA = 23  # Windows Vista, 7
VERSION_8 = 26  # Windows 8, 8.1
VERSION_10 = 30  # Windows 10+


class MAMDecompressionError(Exception):
    """Error during MAM decompression."""

    def __init__(self, message: str, partial_output: bytes | None = None):
        super().__init__(message)
        self.partial_output = partial_output


def decompress_mam(data: bytes) -> bytes:
    """Decompress MAM (LZXPRESS Huffman) compressed prefetch data.

    Windows 10+ uses MAM compression for prefetch files.
    Based on MS-XCA specification for XPRESS Huffman compression.

    MAM file structure:
    - Bytes 0-3: Signature "MAM\\x04"
    - Bytes 4-7: Uncompressed size (uint32 LE)
    - Bytes 8+: Compressed data (XPRESS Huffman chunks)

    Note: XPRESS Huffman decompression is complex and may not work for all files.
    If decompression fails, returns None to indicate unsupported compression.

    Raises:
        MAMDecompressionError: When decompression partially succeeds but encounters
            invalid data. The partial_output attribute contains successfully
            decompressed bytes up to the failure point.
    """
    if len(data) < 8:
        return data

    # MAM header: signature (4) + uncompressed_size (4)
    if data[:4] != PREFETCH_SIGNATURE_MAM:
        return data

    uncompressed_size = struct.unpack("<I", data[4:8])[0]
    compressed_data = data[8:]

    # Try LZXPRESS Huffman decompression
    try:
        decompressed = _xpress_huffman_decompress(compressed_data, uncompressed_size)

        # Verify decompression succeeded by checking for SCCA signature
        # In prefetch format, SCCA is at offset 4 (after version field)
        if len(decompressed) >= 8 and decompressed[4:8] == PREFETCH_SIGNATURE_SCCA:
            return decompressed

        # Partial decompression - check if we got a valid header at least
        if len(decompressed) >= 84 and decompressed[4:8] == PREFETCH_SIGNATURE_SCCA:
            # Got partial valid data - could be used for limited analysis
            raise MAMDecompressionError(
                f"Partial decompression: {len(decompressed)}/{uncompressed_size} bytes",
                partial_output=decompressed,
            )

        # Decompression produced data but not valid prefetch - return None
        return None
    except MAMDecompressionError:
        raise
    except Exception:
        # Decompression failed completely
        return None


class _BitStream:
    """Bit stream reader for XPRESS Huffman decompression.

    XPRESS reads bits MSB-first for Huffman codes. The underlying stream
    is 16-bit little-endian words.

    Bit buffer model (32-bit, left-justified):
    - bits: Contains up to 32 valid bits, LEFT-justified (MSB-aligned)
    - nbits: Number of valid bits in the buffer
    - We peek/consume from the MSB (left) side
    """

    def __init__(self, data: bytes, start_pos: int = 0) -> None:
        self.data = data
        self.pos = start_pos
        self.bits = 0  # Bits left-justified in 32-bit value
        self.nbits = 0  # Number of valid bits

    def init(self) -> None:
        """Initialize the bit buffer by reading first two 16-bit words."""
        # Read first 16-bit word and place in high 16 bits
        if self.pos + 2 <= len(self.data):
            word = struct.unpack("<H", self.data[self.pos:self.pos + 2])[0]
            self.pos += 2
            self.bits = word << 16
        # Read second 16-bit word and place in low 16 bits
        if self.pos + 2 <= len(self.data):
            word = struct.unpack("<H", self.data[self.pos:self.pos + 2])[0]
            self.pos += 2
            self.bits |= word
        self.nbits = 32

    def peek(self, n: int) -> int:
        """Peek at n bits from the MSB side."""
        if n == 0:
            return 0
        return (self.bits >> (32 - n)) & ((1 << n) - 1)

    def skip(self, n: int) -> None:
        """Skip (consume) n bits from the MSB side and refill if needed."""
        self.bits = (self.bits << n) & 0xFFFFFFFF
        self.nbits -= n
        # Refill when we have less than 16 bits
        if self.nbits < 16 and self.pos + 2 <= len(self.data):
            word = struct.unpack("<H", self.data[self.pos:self.pos + 2])[0]
            self.pos += 2
            self.bits += word << (16 - self.nbits)
            self.nbits += 16

    def read_byte(self) -> int:
        """Read a raw byte from the stream (not from bit buffer)."""
        if self.pos >= len(self.data):
            return 0
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_uint16(self) -> int:
        """Read a raw 16-bit LE value from the stream."""
        if self.pos + 2 > len(self.data):
            return 0
        val = struct.unpack("<H", self.data[self.pos:self.pos + 2])[0]
        self.pos += 2
        return val


def _xpress_huffman_decompress(data: bytes, output_size: int) -> bytes:
    """Decompress XPRESS Huffman data (MS-XCA compliant).

    Each chunk: 256-byte Huffman table + compressed data (up to 64KB output).
    Uses MSB-first bit reading with canonical Huffman codes.

    Key insight: Extended match lengths are read as RAW BYTES from the stream,
    NOT from the bit buffer. This is critical for correct decompression.
    """
    output = bytearray()
    pos = 0

    while pos < len(data) and len(output) < output_size:
        # Read 256-byte Huffman table
        if pos + 256 > len(data):
            break

        # Extract symbol bit lengths (512 symbols, 4 bits each)
        code_sizes = []
        for i in range(256):
            byte = data[pos + i]
            code_sizes.append(byte & 0x0F)  # Low nibble: even symbol
            code_sizes.append((byte >> 4) & 0x0F)  # High nibble: odd symbol

        # Build Huffman tree using sorted symbols approach (like dissect)
        # Sort symbols by (code_length, symbol_value)
        symbols = [(code_sizes[i], i) for i in range(512)]
        symbols.sort()

        # Find first symbol with non-zero code length
        first_valid = 0
        for i, (length, _) in enumerate(symbols):
            if length > 0:
                first_valid = i
                break

        # Build decode tree
        class Node:
            __slots__ = ("children", "is_leaf", "symbol")

            def __init__(self) -> None:
                self.symbol = 0
                self.is_leaf = False
                self.children: list = [None, None]

        nodes = [Node() for _ in range(1024)]
        root = nodes[0]

        mask = 0
        bits = 1
        tree_index = 1

        for i in range(first_valid, 512):
            length, symbol = symbols[i]
            if length == 0:
                continue

            node = nodes[tree_index]
            node.symbol = symbol
            node.is_leaf = True

            # Calculate mask for this code
            mask = (mask << (length - bits)) & 0xFFFFFFFF
            bits = length

            # Add leaf to tree
            current = root
            idx = tree_index + 1
            remaining_bits = bits

            while remaining_bits > 1:
                remaining_bits -= 1
                child_idx = (mask >> remaining_bits) & 1
                if current.children[child_idx] is None:
                    current.children[child_idx] = nodes[idx]
                    nodes[idx].is_leaf = False
                    idx += 1
                current = current.children[child_idx]

            current.children[mask & 1] = nodes[tree_index]
            tree_index = idx
            mask += 1

        # Initialize bit stream after Huffman table
        stream = _BitStream(data, pos + 256)
        stream.init()

        chunk_size = 0
        chunk_output_size = min(65536, output_size - len(output))

        while chunk_size < chunk_output_size and stream.pos < len(data):
            # Decode symbol by walking the tree
            node = root
            while not node.is_leaf:
                bit = stream.peek(1)
                stream.skip(1)
                if node.children[bit] is None:
                    # Invalid tree path
                    output.extend(output[-chunk_size:] if chunk_size > 0 else b"")
                    return bytes(output[:output_size])
                node = node.children[bit]

            symbol = node.symbol

            if symbol < 256:
                # Literal byte
                output.append(symbol)
                chunk_size += 1
            else:
                # Match
                symbol -= 256
                length = symbol & 0x0F
                offset_bits = symbol >> 4

                # Get offset from bit buffer BEFORE reading extended length
                offset = (1 << offset_bits) + stream.peek(offset_bits) if offset_bits > 0 else 1

                # Handle extended length - READ FROM RAW BYTE STREAM
                if length == 15:
                    length = stream.read_byte() + 15
                    if length == 270:  # 15 + 255
                        length = stream.read_uint16()

                # Now skip the offset bits from the bit buffer
                stream.skip(offset_bits)

                length += 3

                # Copy match bytes (can overlap)
                remaining = length
                while remaining > 0:
                    match_size = min(remaining, offset)
                    src_start = len(output) - offset
                    if src_start < 0:
                        # Invalid offset
                        return bytes(output[:output_size])
                    output.extend(output[src_start:src_start + match_size])
                    remaining -= match_size

                chunk_size += length

        pos = stream.pos

    return bytes(output[:output_size])


class PrefetchFile:
    """Parsed Prefetch file structure."""

    def __init__(self, data: bytes) -> None:
        """Initialize from raw prefetch data."""
        self.data = data
        self.version: int = 0
        self.executable_name: str = ""
        self.prefetch_hash: int = 0
        self.file_size: int = 0
        self.run_count: int = 0
        self.last_run_times: list[datetime] = []
        self.file_references: list[str] = []
        self.volume_info: list[dict[str, Any]] = []
        self._scca_offset: int = 0  # 0 for v17, 4 for v23+

        self._parse()

    def _parse(self) -> None:
        """Parse prefetch file structure."""
        if len(self.data) < 84:
            raise ValueError("Prefetch file too small")

        if self.data[:4] == PREFETCH_SIGNATURE_MAM:
            # Compressed prefetch (Win10+)
            try:
                decompressed = decompress_mam(self.data)
            except MAMDecompressionError as e:
                # Partial decompression - try to use what we got
                if e.partial_output and len(e.partial_output) >= 84:
                    decompressed = e.partial_output
                else:
                    raise ValueError(
                        f"MAM decompression failed: {e}. "
                        "Use external tools to decompress first."
                    )

            if decompressed is None:
                raise ValueError(
                    "Windows 10+ compressed prefetch (MAM/XPRESS Huffman) - "
                    "decompression failed. The file may be corrupted or use "
                    "an unsupported compression variant. "
                    "Use external tools to decompress first."
                )
            self.data = decompressed

        # Check for SCCA signature - location varies by version:
        # - Version 17 (XP): SCCA at offset 0, version follows
        # - Version 23+ (Vista+): Version at offset 0, SCCA at offset 4
        if self.data[0:4] == PREFETCH_SIGNATURE_SCCA:
            # Version 17 format: SCCA at start
            self._scca_offset = 0
        elif self.data[4:8] == PREFETCH_SIGNATURE_SCCA:
            # Version 23+ format: version at start, SCCA at offset 4
            self._scca_offset = 4
        else:
            raise ValueError(
                f"Invalid prefetch signature: not found at offset 0 ({self.data[0:4]!r}) "
                f"or offset 4 ({self.data[4:8]!r})"
            )

        self._parse_header()

        if self.version == VERSION_XP:
            self._parse_v17()
        elif self.version == VERSION_VISTA:
            self._parse_v23()
        elif self.version == VERSION_8:
            self._parse_v26()
        elif self.version == VERSION_10:
            self._parse_v30()
        else:
            self._parse_generic()

    def _parse_header(self) -> None:
        """Parse prefetch file header."""
        # Header structure varies by format:
        #
        # Version 17 (XP) - SCCA at offset 0:
        # 0-4: Signature "SCCA"
        # 4-8: Format version
        # 8-12: Unknown
        # 12-16: File size
        # 16-76: Executable name (60 bytes, UTF-16LE)
        # 76-80: Prefetch hash
        # 80-84: Unknown flags
        #
        # Version 23+ (Vista+) - SCCA at offset 4:
        # 0-4: Format version
        # 4-8: Signature "SCCA"
        # 8-12: Unknown
        # 12-16: File size
        # 16-76: Executable name (60 bytes, UTF-16LE)
        # 76-80: Prefetch hash
        # 80-84: Unknown flags

        if self._scca_offset == 0:
            # Version 17 format: SCCA at start, version follows
            self.version = struct.unpack("<I", self.data[4:8])[0]
        else:
            # Version 23+ format: version at start
            self.version = struct.unpack("<I", self.data[0:4])[0]

        self.file_size = struct.unpack("<I", self.data[12:16])[0]

        # Extract executable name (UTF-16LE, null-terminated)
        name_bytes = self.data[16:76]
        try:
            self.executable_name = name_bytes.decode("utf-16-le").split("\x00")[0]
        except UnicodeDecodeError:
            self.executable_name = ""

        self.prefetch_hash = struct.unpack("<I", self.data[76:80])[0]

    def _parse_v17(self) -> None:
        """Parse version 17 (Windows XP) prefetch."""
        if len(self.data) < 156:
            return

        # File info at offset 84
        # 84-88: Section A offset (file metrics)
        # 88-92: Section A entries
        # 92-96: Section B offset (trace chains)
        # 96-100: Section B entries
        # 100-104: Section C offset (filename strings)
        # 104-108: Section C length
        # 108-112: Section D offset (volume info)
        # 112-116: Section D entries
        # 116-120: Section D length
        # 120-128: Last run time (FILETIME)
        # 128-144: Unknown
        # 144-148: Run count
        # 148-152: Unknown

        section_a_offset = struct.unpack("<I", self.data[84:88])[0]
        section_a_entries = struct.unpack("<I", self.data[88:92])[0]
        section_c_offset = struct.unpack("<I", self.data[100:104])[0]
        section_c_length = struct.unpack("<I", self.data[104:108])[0]
        section_d_offset = struct.unpack("<I", self.data[108:112])[0]
        section_d_entries = struct.unpack("<I", self.data[112:116])[0]

        last_run_filetime = struct.unpack("<Q", self.data[120:128])[0]
        if last_run_filetime > 0:
            self.last_run_times.append(self._filetime_to_datetime(last_run_filetime))

        self.run_count = struct.unpack("<I", self.data[144:148])[0]

        self._parse_filename_strings(section_c_offset, section_c_length)
        self._parse_volume_info_v17(section_d_offset, section_d_entries)

    def _parse_v23(self) -> None:
        """Parse version 23 (Windows Vista/7) prefetch."""
        if len(self.data) < 240:
            return

        # Similar to v17 but with different offsets
        section_a_offset = struct.unpack("<I", self.data[84:88])[0]
        section_a_entries = struct.unpack("<I", self.data[88:92])[0]
        section_c_offset = struct.unpack("<I", self.data[100:104])[0]
        section_c_length = struct.unpack("<I", self.data[104:108])[0]
        section_d_offset = struct.unpack("<I", self.data[108:112])[0]
        section_d_entries = struct.unpack("<I", self.data[112:116])[0]

        # Last run time at offset 128
        last_run_filetime = struct.unpack("<Q", self.data[128:136])[0]
        if last_run_filetime > 0:
            self.last_run_times.append(self._filetime_to_datetime(last_run_filetime))

        self.run_count = struct.unpack("<I", self.data[152:156])[0]

        self._parse_filename_strings(section_c_offset, section_c_length)
        self._parse_volume_info_v23(section_d_offset, section_d_entries)

    def _parse_v26(self) -> None:
        """Parse version 26 (Windows 8/8.1) prefetch."""
        if len(self.data) < 304:
            return

        section_a_offset = struct.unpack("<I", self.data[84:88])[0]
        section_a_entries = struct.unpack("<I", self.data[88:92])[0]
        section_c_offset = struct.unpack("<I", self.data[100:104])[0]
        section_c_length = struct.unpack("<I", self.data[104:108])[0]
        section_d_offset = struct.unpack("<I", self.data[108:112])[0]
        section_d_entries = struct.unpack("<I", self.data[112:116])[0]

        # 8 last run times starting at offset 128
        for i in range(8):
            offset = 128 + (i * 8)
            if offset + 8 <= len(self.data):
                filetime = struct.unpack("<Q", self.data[offset:offset + 8])[0]
                if filetime > 0:
                    self.last_run_times.append(self._filetime_to_datetime(filetime))

        self.run_count = struct.unpack("<I", self.data[200:204])[0] if len(self.data) > 204 else 0

        self._parse_filename_strings(section_c_offset, section_c_length)
        self._parse_volume_info_v26(section_d_offset, section_d_entries)

    def _parse_v30(self) -> None:
        """Parse version 30 (Windows 10+) prefetch."""
        # V30 has same structure as v26 after decompression
        self._parse_v26()

    def _parse_generic(self) -> None:
        """Generic parsing for unknown versions."""
        # Try to extract basic info
        if len(self.data) > 128:
            # Attempt to find run count and timestamps
            for offset in [120, 128, 144, 152, 200]:
                if offset + 8 <= len(self.data):
                    filetime = struct.unpack("<Q", self.data[offset:offset + 8])[0]
                    if 120000000000000000 < filetime < 140000000000000000:
                        # Looks like a valid FILETIME
                        self.last_run_times.append(self._filetime_to_datetime(filetime))
                        break

    def _parse_filename_strings(self, offset: int, length: int) -> None:
        """Parse filename strings section."""
        if offset + length > len(self.data):
            return

        string_data = self.data[offset:offset + length]

        # Strings are null-terminated UTF-16LE
        pos = 0
        while pos < len(string_data) - 1:
            # Find null terminator
            end = pos
            while end < len(string_data) - 1:
                if string_data[end:end + 2] == b"\x00\x00":
                    break
                end += 2

            if end > pos:
                try:
                    filename = string_data[pos:end].decode("utf-16-le")
                    if filename and len(filename) > 1:
                        self.file_references.append(filename)
                except UnicodeDecodeError:
                    pass

            pos = end + 2

    def _parse_volume_info_v17(self, offset: int, entries: int) -> None:
        """Parse volume info for version 17."""
        if offset >= len(self.data):
            return

        # Volume info entry is 40 bytes in v17
        entry_size = 40
        for i in range(min(entries, 10)):  # Limit to 10 volumes
            entry_offset = offset + (i * entry_size)
            if entry_offset + entry_size > len(self.data):
                break

            vol_path_offset = struct.unpack("<I", self.data[entry_offset:entry_offset + 4])[0]
            vol_path_length = struct.unpack("<I", self.data[entry_offset + 4:entry_offset + 8])[0]
            vol_creation_time = struct.unpack("<Q", self.data[entry_offset + 8:entry_offset + 16])[0]
            vol_serial = struct.unpack("<I", self.data[entry_offset + 16:entry_offset + 20])[0]

            # Read volume path
            vol_path = ""
            if vol_path_offset + vol_path_length * 2 <= len(self.data):
                try:
                    vol_path = self.data[vol_path_offset:vol_path_offset + vol_path_length * 2].decode("utf-16-le").rstrip("\x00")
                except UnicodeDecodeError:
                    pass

            self.volume_info.append({
                "path": vol_path,
                "creation_time": self._filetime_to_datetime(vol_creation_time) if vol_creation_time > 0 else None,
                "serial_number": f"{vol_serial:08X}",
            })

    def _parse_volume_info_v23(self, offset: int, entries: int) -> None:
        """Parse volume info for version 23."""
        # Similar to v17 but 104 bytes per entry
        self._parse_volume_info_generic(offset, entries, 104)

    def _parse_volume_info_v26(self, offset: int, entries: int) -> None:
        """Parse volume info for version 26/30."""
        # 96 bytes per entry
        self._parse_volume_info_generic(offset, entries, 96)

    def _parse_volume_info_generic(self, offset: int, entries: int, entry_size: int) -> None:
        """Generic volume info parser."""
        if offset >= len(self.data):
            return

        for i in range(min(entries, 10)):
            entry_offset = offset + (i * entry_size)
            if entry_offset + 24 > len(self.data):
                break

            vol_path_offset = struct.unpack("<I", self.data[entry_offset:entry_offset + 4])[0]
            vol_path_length = struct.unpack("<I", self.data[entry_offset + 4:entry_offset + 8])[0]
            vol_creation_time = struct.unpack("<Q", self.data[entry_offset + 8:entry_offset + 16])[0]
            vol_serial = struct.unpack("<I", self.data[entry_offset + 16:entry_offset + 20])[0]

            # Volume path is relative to volume info section
            vol_path_abs = offset + vol_path_offset
            vol_path = ""
            if vol_path_abs + vol_path_length * 2 <= len(self.data):
                try:
                    vol_path = self.data[vol_path_abs:vol_path_abs + vol_path_length * 2].decode("utf-16-le").rstrip("\x00")
                except UnicodeDecodeError:
                    pass

            if vol_path or vol_serial:
                self.volume_info.append({
                    "path": vol_path,
                    "creation_time": self._filetime_to_datetime(vol_creation_time) if vol_creation_time > 0 else None,
                    "serial_number": f"{vol_serial:08X}",
                })

    @staticmethod
    def _filetime_to_datetime(filetime: int) -> datetime:
        """Convert Windows FILETIME to datetime."""
        # FILETIME: 100-nanosecond intervals since 1601-01-01
        unix_ts = (filetime - 116444736000000000) / 10000000
        try:
            return datetime.fromtimestamp(unix_ts, tz=UTC)
        except (OSError, ValueError):
            return datetime.min.replace(tzinfo=UTC)


@ParserRegistry.register
class PrefetchParser(BaseParser):
    """Parser for Windows Prefetch files.

    Supports versions 17 (XP), 23 (Vista/7), 26 (8/8.1), and 30 (Win10+).
    """

    name: ClassVar[str] = "prefetch"
    version: ClassVar[str] = PARSER_VERSION
    supported_artifacts: ClassVar[list[str]] = ["prefetch"]

    def __init__(
        self,
        target_id: UUID,
        artifact_path: str,
        source_hash: str,
        timezone_str: str = "UTC",
    ) -> None:
        """Initialize Prefetch parser."""
        super().__init__(target_id, artifact_path, source_hash, timezone_str)

    def parse(self, file_path: Path) -> Iterator[ParsedRecord]:
        """Parse Prefetch file and yield records.

        Args:
            file_path: Path to Prefetch file

        Yields:
            ParsedRecord for each prefetch file
        """
        with open(file_path, "rb") as fh:
            data = fh.read()

        yield from self.parse_bytes(data)

    def parse_bytes(self, data: bytes) -> Iterator[ParsedRecord]:
        """Parse Prefetch from raw bytes.

        Args:
            data: Raw Prefetch file content

        Yields:
            ParsedRecord with prefetch information

        Raises:
            ValueError: If the prefetch file cannot be parsed
        """
        pf = PrefetchFile(data)

        timestamp = pf.last_run_times[0] if pf.last_run_times else None
        record_data: dict[str, Any] = {
            "executable_name": pf.executable_name,
            "prefetch_hash": f"{pf.prefetch_hash:08X}",
            "version": pf.version,
            "run_count": pf.run_count,
        }

        if pf.last_run_times:
            record_data["last_run_times"] = [
                t.isoformat() for t in pf.last_run_times
            ]

        if pf.file_references:
            record_data["file_count"] = len(pf.file_references)
            record_data["file_references"] = pf.file_references[:100]

        if pf.volume_info:
            record_data["volumes"] = []
            for vol in pf.volume_info:
                vol_entry = {"path": vol["path"], "serial": vol["serial_number"]}
                if vol.get("creation_time"):
                    vol_entry["creation_time"] = vol["creation_time"].isoformat()
                record_data["volumes"].append(vol_entry)

        record_id = self.create_record_id(
            "prefetch",
            pf.executable_name,
            pf.prefetch_hash,
        )

        yield ParsedRecord(
            record_id=record_id,
            schema_version="v1",
            record_type="timeline",
            timestamp=self.normalize_timestamp(timestamp),
            timestamp_original=timestamp.isoformat() if timestamp else None,
            data=record_data,
            evidence_ref=self.create_evidence_ref(
                record_offset=0,
                record_index=0,
            ),
        )


def parse_prefetch(
    file_path: Path,
    target_id: UUID,
    artifact_path: str,
    source_hash: str,
    timezone_str: str = "UTC",
) -> Iterator[ParsedRecord]:
    """Convenience function to parse a Prefetch file.

    Args:
        file_path: Path to Prefetch file
        target_id: Target UUID
        artifact_path: Artifact path for evidence_ref
        source_hash: SHA-256 of artifact
        timezone_str: Output timezone

    Yields:
        ParsedRecord for each prefetch entry
    """
    parser = PrefetchParser(
        target_id=target_id,
        artifact_path=artifact_path,
        source_hash=source_hash,
        timezone_str=timezone_str,
    )
    yield from parser.parse(file_path)
