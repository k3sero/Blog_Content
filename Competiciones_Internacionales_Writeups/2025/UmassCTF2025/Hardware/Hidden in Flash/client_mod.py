import os
import re
import sys
import subprocess
import socket
import time

START = 0
TOTAL = 4 * 1024
HOST = "hardware.ctf.umasscybersec.org"
PORT = 10003
BUILD_DIR = "build"


def update_bounds(sketch_name="eeprom_dump.ino"):
    path = os.path.join('.', sketch_name)
    with open(path, 'r') as f:
        code = f.read()

    new_line = f"const uint32_t TOTAL   = {TOTAL};\n"
    pattern = r"const\s+uint\d+_t\s+TOTAL\s*=.*?;"
    updated_code, count = re.subn(pattern, new_line.strip(), code)
    if count == 0:
        print("WARNING: No TOTAL definition found")

    new_line = f"const uint32_t START   = {START};\n"
    pattern = r"const\s+uint\d+_t\s+START\s*=.*?;"
    updated_code, count = re.subn(pattern, new_line.strip(), updated_code)
    if count == 0:
        print("WARNING: No START definition found")

    with open(path, 'w') as f:
        f.write(updated_code)
    print(f"Updated TOTAL&START in {sketch_name}.")


def compile_sketch():
    cmd = [
        "arduino-cli", "compile",
        "--fqbn", "arduino:avr:uno",
        "--build-path", 'build',
        '.'
    ]
    print("Compiling sketch...")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Compilation failed: {e}")
        sys.exit(1)

    build_path = os.path.join('.', BUILD_DIR)
    return os.path.join(build_path, "eeprom_dump.ino.elf")


def send_firmware(elf_path):
    with open(elf_path, 'rb') as f:
        data = f.read()

    time_err = TimeoutError("Did not receive expected data in time.")

    def recv(sock, num_bytes, timeout=5.0):
        output = b''
        start = time.time()
        while num_bytes > 0 and time.time() - start < timeout:
            recvd = sock.recv(num_bytes)
            if not recvd:
                break
            num_bytes -= len(recvd)
            output += recvd
        if num_bytes:
            raise time_err
        return output

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print("Connecting...")
        s.connect((HOST, PORT))
        print("Sending firmware...")
        s.sendall(len(data).to_bytes(4, 'little') + data)
        if recv(s, 1) != b"\x00":
            print("Unknown response from server")
            sys.exit(1)

        print("Running code...")
        rsp_msgs = [
            "Code ran successfully!",
            "Internal error setting up sim."
            "The sim crashed while running your code."
        ]
        ret = int.from_bytes(recv(s, 1), 'little')
        if ret < len(rsp_msgs):
            print(rsp_msgs[ret])
        else:
            print("Unknown response from server")
        out_len = int.from_bytes(recv(s, 4), 'little')
        data = recv(s, out_len)
        return data


def main():
    global TOTAL, START
    all_data = b''
    total_iterations = 16
    for i in range(total_iterations):
        START = i * 1024*4
        TOTAL = (i + 1) * 1024*4
        print(f"Trying with START={START} and TOTAL={TOTAL}")
        update_bounds()
        elf = compile_sketch()
        data = send_firmware(elf)
        all_data += data
        print(f"Received {len(data)} bytes of data.")
        print(f"{i}/{total_iterations}")
    print("Writing data to eeprom_dump.bin")
    with open("eeprom_dump.bin", "wb") as f:
        f.write(all_data)
    print("Done!")


if __name__ == '__main__':
    main()