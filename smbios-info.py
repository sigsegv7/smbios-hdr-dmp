import os

ENDIANNESS = "little"

def read_dev_mem(address: int, size: int) -> bytes:
    fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
    os.lseek(fd, address, os.SEEK_SET)

    mem_bytes = os.read(fd, size)
    os.close(fd)

    return mem_bytes

def find_smbios_entrypoint() -> int | None:
    for addr in range(0xF0000, 0x100000, 4):
        signature = read_dev_mem(addr, 4)
        if signature == b'_SM_':
            print(f"Found SMBIOS entrypoint @{hex(addr)}")
            return addr

    return None

def compute_checksum(data: bytes) -> bool:
    return (sum(data) & 0xFF) == 0

def get_header_length(entrypoint: int) -> int:
    length = read_dev_mem(entrypoint + 5, 1)
    length = int.from_bytes(length, ENDIANNESS)
    return length

def verify_checksum(entrypoint: int) -> bool:
    length = get_header_length(entrypoint)

    print(f"SMBIOS Header Length: {length} bytes")
    data = read_dev_mem(entrypoint, length)
    return compute_checksum(data[::-1])

def smbios_dump_header(entrypoint: int):
    hdr_len = get_header_length(entrypoint)
    data = read_dev_mem(entrypoint, hdr_len)
    print(f"SMBIOS HEADER: {data}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run as root!")
        exit(1)

    entrypoint = find_smbios_entrypoint()
    if entrypoint is None:
        print("Failure to fetch SMBIOS entrypoint!")
        exit(1)

    csum_valid = verify_checksum(entrypoint)

    if not csum_valid:
        print("Checksum: BAD")
        exit(1)

    print("Checksum: OK")
    smbios_dump_header(entrypoint)
