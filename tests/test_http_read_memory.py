# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import io
import tracemalloc
import unittest
from unittest.mock import patch

from census.common import request_bytes


class SmallRaw(io.RawIOBase):
    def __init__(self, payload: bytes, width: int | None = None):
        self.payload = payload
        self.position = 0
        self.width = width

    def readable(self):
        return True

    def readinto(self, buffer):
        size = min(len(buffer), len(self.payload) - self.position)
        if self.width is not None:
            size = min(size, self.width)
        buffer[:size] = self.payload[self.position:self.position + size]
        self.position += size
        return size


class BufferedResponse(io.BufferedReader):
    def __init__(self, payload: bytes, *, width: int | None = None, headers=None):
        super().__init__(SmallRaw(payload, width))
        self.headers = {} if headers is None else headers
        self.read_sizes: list[int] = []

    def read(self, size=-1):
        self.read_sizes.append(size)
        return super().read(size)


class HttpReadMemoryTests(unittest.TestCase):
    def request(self, response, max_bytes):
        with patch("census.common.urllib.request.build_opener") as opener:
            opener.return_value.open.return_value = response
            return request_bytes(
                "https://api.github.com/items", max_bytes=max_bytes, retries=0
            )

    def test_tiny_response_does_not_allocate_the_archive_ceiling(self):
        payload = b"x" * 4096
        response = BufferedResponse(payload)
        tracemalloc.start()
        try:
            body, _, error = self.request(response, 512 * 1024 * 1024)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(body, payload)
        self.assertIsNone(error)
        self.assertLess(peak, 8 * 1024 * 1024)
        self.assertTrue(all(0 < size <= 1024 * 1024 for size in response.read_sizes))

    def test_multiple_chunks_and_short_raw_reads_preserve_every_byte(self):
        payload = bytes(range(256)) * 9000
        for width in (None, 8191):
            with self.subTest(width=width):
                body, _, error = self.request(
                    BufferedResponse(payload, width=width), len(payload)
                )
                self.assertEqual(body, payload)
                self.assertIsNone(error)

    def test_ceiling_and_one_byte_overflow_without_content_length(self):
        for size in (0, 15, 16, 17):
            with self.subTest(size=size):
                payload = b"x" * size
                body, _, error = self.request(BufferedResponse(payload), 16)
                if size > 16:
                    self.assertIsNone(body)
                    self.assertEqual(error, "response-body-limit-exceeded")
                else:
                    self.assertEqual(body, payload)
                    self.assertIsNone(error)

    def test_overflow_after_full_chunk_is_rejected(self):
        ceiling = 1024 * 1024
        response = BufferedResponse(b"x" * (ceiling + 1))
        body, _, error = self.request(response, ceiling)
        self.assertIsNone(body)
        self.assertEqual(error, "response-body-limit-exceeded")
        self.assertEqual(response.read_sizes, [ceiling, 1])

    def test_declared_oversize_is_rejected_before_reading(self):
        response = BufferedResponse(b"x", headers={"Content-Length": "17"})
        body, _, error = self.request(response, 16)
        self.assertIsNone(body)
        self.assertEqual(error, "response-body-limit-exceeded")
        self.assertEqual(response.read_sizes, [])


if __name__ == "__main__":
    unittest.main()
