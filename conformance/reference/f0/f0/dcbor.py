MAX_DEPTH = 16
MAX_ITEMS = 256
MAX_STRING = 65536


class DecodeError(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


class Reader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, count):
        if self.offset + count > len(self.data):
            raise DecodeError("truncated")
        chunk = self.data[self.offset:self.offset + count]
        self.offset += count
        return chunk

    def read_argument(self, additional):
        # OP-106 m.1
        if additional < 24:
            return additional
        size = {24: 1, 25: 2, 26: 4, 27: 8}[additional]
        value = int.from_bytes(self.take(size), "big")
        smallest = {1: 24, 2: 2**8, 4: 2**16, 8: 2**32}[size]
        if value < smallest:
            raise DecodeError("non-shortest")
        return value

    def read_item(self, depth, allowed_tag=None):
        initial = self.take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F
        if additional in (28, 29, 30):
            raise DecodeError("reserved")
        if additional == 31:
            # OP-106 m.1
            if major in (2, 3, 4, 5, 7):
                raise DecodeError("indefinite")
            raise DecodeError("reserved")
        if major == 7:
            if additional in (25, 26, 27):
                # OP-106 m.2
                raise DecodeError("float")
            if additional in (20, 21):
                return
            # OP-106 m.4
            raise DecodeError("simple")
        if major == 6:
            # OP-106 m.3
            if allowed_tag is None:
                raise DecodeError("tag")
            if self.read_argument(additional) != allowed_tag:
                raise DecodeError("tag")
            self.read_item(depth)
            return
        if major in (4, 5) and depth + 1 > MAX_DEPTH:
            # OP-117 m.3
            raise DecodeError("depth")
        argument = self.read_argument(additional)
        if major in (0, 1):
            return
        if major in (2, 3):
            # OP-117 m.4
            if argument > MAX_STRING:
                raise DecodeError("string-length")
            content = self.take(argument)
            if major == 3:
                try:
                    content.decode("utf-8")
                except UnicodeDecodeError:
                    raise DecodeError("utf8")
            return
        # OP-106 m.5
        if argument > MAX_ITEMS:
            raise DecodeError("items")
        if major == 4:
            for _ in range(argument):
                self.read_item(depth + 1)
            return
        previous_key = None
        for _ in range(argument):
            start = self.offset
            self.read_item(depth + 1)
            key = self.data[start:self.offset]
            # OP-106 m.1
            if previous_key is not None:
                if key == previous_key:
                    raise DecodeError("duplicate-key")
                if key < previous_key:
                    raise DecodeError("key-order")
            previous_key = key
            self.read_item(depth + 1)


def check(data, allowed_tag=None):
    reader = Reader(data)
    reader.read_item(0, allowed_tag)
    if reader.offset != len(data):
        raise DecodeError("trailing-bytes")
