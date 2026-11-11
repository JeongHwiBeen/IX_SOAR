"""TCP syslog messages: RFC 6587 octet-counting or LF/NUL delimiter."""


class FrameTooLarge(ValueError):
    pass


class SyslogFramer:

    def __init__(self, mode: str = "auto", limit: int = 65536):

        if mode not in {"auto", "line", "octet"}:
            raise ValueError(
                "TCP_FRAMING must be auto, line, or octet"
            )

        self.mode = mode
        self.limit = limit
        self.buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:

        self.buf.extend(data)
        frames = []

        while self.buf:
            mode = self.mode

            if mode == "auto":

                digits = 0

                while (
                    digits < len(self.buf)
                    and 48 <= self.buf[digits] <= 57
                ):
                    digits += 1

                if digits and digits == len(self.buf):
                    if digits > 10:
                        raise FrameTooLarge(
                            "invalid octet length header"
                        )
                    break

                mode = (
                    "octet"
                    if digits and self.buf[digits:digits + 1] == b" "
                    else "line"
                )

            if mode == "octet":

                pos = self.buf.find(b" ")

                if pos == -1:
                    if len(self.buf) > 10:
                        raise FrameTooLarge("invalid octet prefix")
                    break

                prefix = bytes(self.buf[:pos])

                if not prefix.isdigit() or prefix.startswith(b"0"):
                    raise ValueError("invalid octet length")

                length = int(prefix)

                if not 1 <= length <= self.limit:
                    raise FrameTooLarge("oversized syslog frame")

                end = pos + 1 + length

                if len(self.buf) < end:
                    break

                frames.append(
                    bytes(self.buf[pos + 1:end])
                )

                del self.buf[:end]

            else:

                endings = [
                    p for p in (
                        self.buf.find(b"\n"),
                        self.buf.find(b"\0")
                    )
                    if p >= 0
                ]

                if not endings:
                    if len(self.buf) > self.limit:
                        raise FrameTooLarge(
                            "oversized syslog frame"
                        )
                    break

                pos = min(endings)

                if pos > self.limit:
                    raise FrameTooLarge("oversized syslog frame")

                msg = bytes(self.buf[:pos]).rstrip(b"\r")

                del self.buf[:pos + 1]

                if msg:
                    frames.append(msg)

        return frames