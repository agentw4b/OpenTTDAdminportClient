import socket, struct, threading, time, re
from datetime import datetime, timezone, timedelta

# --- CONFIG ---
host = "192.168.0.101"
port = 3977
password = "jitrew47"

# --- PACKETS ---
ADMIN_JOIN, ADMIN_QUIT, ADMIN_UPDATE_FREQUENCY, ADMIN_CHAT, ADMIN_RCON, ADMIN_PING, ADMIN_POLL = 0, 1, 2, 4, 5, 7, 3
SERVER_PROTOCOL, SERVER_WELCOME = 103, 104
SERVER_DATE, SERVER_CLIENT_JOIN, SERVER_CLIENT_INFO = 105, 110, 111
SERVER_CLIENT_UPDATE, SERVER_CLIENT_QUIT = 112, 113
SERVER_COMPANY_NEW, SERVER_COMPANY_INFO, SERVER_COMPANY_UPDATE = 115, 116, 117
SERVER_CHAT, SERVER_CONSOLE, SERVER_PONG = 123, 107, 126
SERVER_GAMESCRIPT, SERVER_RCON = 124, 121

FREQ_POLL, FREQ_DAILY, FREQ_AUTOMATIC = 1, 2, 64

# --- GLOBALS ---
sock = None
log_admin = []
joined = False
welcomed = False
ping_time = None

# --- HELPERS ---
def replace_nonprintables(text):
    return re.sub(r'[^ -~]', lambda m: f"[x{ord(m.group(0)):02x}]", text)

pc = lambda n: {"7":"\033[90m","104":"\033[36m","121":"\033[33m","107":"\033[32m","126":"\033[91m"}.get(str(n), "\033[0m")
ct = lambda text, c: f"{c}{text}\033[0m"

def send_packet(ptype, payload):
    data = struct.pack("<HB", len(payload)+3, ptype) + payload
    sock.sendall(data)
    print(ct(f"[SEND {ptype}] {payload[:40]!r}", pc(ptype)))

def recvall(n):
    d = b""
    while len(d) < n:
        try:
            p = sock.recv(n - len(d))
            if not p:
                raise ConnectionError
            d += p
        except socket.timeout:
            continue
    return d

def start_updates():
    for ut in (0, 5, 6):
        send_packet(ADMIN_UPDATE_FREQUENCY, struct.pack("<HBH", ut, FREQ_AUTOMATIC, 0))
    for ut in (1, 2, 9):
        send_packet(ADMIN_UPDATE_FREQUENCY, struct.pack("<HBH", ut, FREQ_POLL, 0))

def poll_updates():
    for ut in (1, 2, 9):
        send_packet(ADMIN_POLL, struct.pack("<BI", ut, 0xFFFFFFFF))

def decode_client(pl):
    cid = struct.unpack_from("<I", pl, 0)[0]
    return f"Client ID: {cid}, raw: {replace_nonprintables(pl[4:].decode(errors='ignore'))}"

def decode_company(pl):
    cid = struct.unpack_from("<B", pl, 0)[0]
    return f"Company ID: {cid}, raw: {replace_nonprintables(pl[1:].decode(errors='ignore'))}"

# --- RECV LOOP ---
def recv_loop():
    global joined, welcomed, ping_time
    while True:
        h = recvall(3)
        length, ptype = struct.unpack("<HB", h)
        pl = recvall(length - 3)

        if ptype == SERVER_PROTOCOL:
            joined = True

        elif ptype == SERVER_WELCOME and joined:
            welcomed = True
            print(ct(">>> Received WELCOME — enabling updates", pc(ptype)))
            start_updates()

        elif ptype in (
            SERVER_DATE, SERVER_CLIENT_INFO, SERVER_CLIENT_UPDATE,
            SERVER_COMPANY_INFO, SERVER_COMPANY_UPDATE,
            SERVER_GAMESCRIPT, SERVER_CHAT, SERVER_CONSOLE, SERVER_RCON, SERVER_PONG
        ):
            if ptype == SERVER_DATE:
                game_date, = struct.unpack("<I", pl)
                print(ct(f"[DATE] {game_date}", pc(ptype)))
            elif ptype in (SERVER_CLIENT_INFO, SERVER_CLIENT_UPDATE):
                print(ct("[CLIENT] " + decode_client(pl), pc(ptype)))
            elif ptype in (SERVER_COMPANY_INFO, SERVER_COMPANY_UPDATE):
                print(ct("[COMPANY] " + decode_company(pl), pc(ptype)))
            elif ptype == SERVER_GAMESCRIPT:
                print(ct("[GAMESCRIPT] " + pl.decode(errors='ignore'), pc(ptype)))
            elif ptype == SERVER_CHAT:
                print(ct("[CHAT] " + pl.decode(errors='ignore'), pc(ptype)))
            elif ptype == SERVER_PONG:
                val, = struct.unpack("<I", pl)
                rtt = int((time.time() - ping_time) * 1000) if ping_time else -1
                print(ct(f"[PONG] {val}, RTT {rtt} ms", pc(ptype)))
                ping_time = None
            elif ptype in (SERVER_CONSOLE, SERVER_RCON):
                log_admin.append((ptype, pl))
        elif ptype in (107, 121):
            log_admin.append((ptype, pl))
        else:
            print(ct(f"[{ptype}] RAW {pl[:50]!r}", pc(ptype)))

# --- MAIN ---
def main():
    global sock, ping_time
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(0.5)
    print("CONNECTED")
    threading.Thread(target=recv_loop, daemon=True).start()

    send_packet(ADMIN_JOIN, password.encode() + b'\0TestBot\0v1.0\0')
    time.sleep(1)

    while True:
        cmd = input("\nMENU: 1=log 2=rcon 3=ping 4=chat 5=poll info 6=quit\n> ").strip()
        if cmd == "1":
            print("----- LOG (console/rcon) -----")
            for ptype, pl in log_admin:
                s = replace_nonprintables(pl.decode(errors='ignore'))
                print(ct(f"[{ptype}] {s}", pc(ptype)))
            input("Enter →")
        elif cmd == "2":
            cmd = input("RCON cmd: ") + "\0"
            send_packet(ADMIN_RCON, cmd.encode())
        elif cmd == "3":
            ping_time = time.time()
            send_packet(ADMIN_PING, struct.pack("<I", int(ping_time)))
        elif cmd == "4":
            msg = input("Chat msg: ")
            payload = struct.pack("<IBI", 1, 2, 0) + msg.encode() + b'\0'
            send_packet(ADMIN_CHAT, payload)
        elif cmd == "5":
            poll_updates()
        elif cmd == "6":
            break

if __name__ == "__main__":
    main()
