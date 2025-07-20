import socket, struct, threading, time, re
from datetime import datetime, timedelta, timezone

# --- CONFIG ---
host = "192.168.0.101"
port = 3977
password = "jitrew47"

# --- PACKETS ---
ADMIN_JOIN, ADMIN_QUIT, ADMIN_UPDATE_FREQUENCY, ADMIN_CHAT, ADMIN_RCON, ADMIN_PING = 0, 1, 2, 4, 5, 7
SERVER_PROTOCOL, SERVER_WELCOME, SERVER_RCON, SERVER_CONSOLE, SERVER_PONG, SERVER_TEXT = 103, 104, 121, 107, 126, 120
FREQ_POLL, FREQ_DAILY, FREQ_AUTOMATIC = 1, 2, 64

# --- GLOBALS ---
log_admin = []
sock = None
rcon_active = False
ping_time = None

def replace_nonprintables(text):
    return re.sub(r'[^ -~]', lambda m: f"[x{ord(m.group(0)):02x}]", text)

# ANSI colors
pc = lambda n: {
    "7": "\033[90m", "104": "\033[36m", "121": "\033[33m", "107": "\033[32m", "126": "\033[91m"
}.get(str(n), "\033[0m")
def ct(text, c): return f"{c}{text}\033[0m"

def decode_send(ptype, payload):
    try:
        if ptype == ADMIN_CHAT:
            return f"CHAT: {payload[9:-1].decode()}"
        if ptype == ADMIN_RCON:
            return f"RCON: {payload[:-1].decode()}"
        if ptype == ADMIN_PING:
            return f"PING: {struct.unpack('<I', payload)[0]}"
        if ptype == ADMIN_UPDATE_FREQUENCY:
            u, f, _ = struct.unpack("<HBH", payload)
            return f"UPDATE type={u} freq={f}"
        return payload.decode(errors='ignore')
    except:
        return payload.hex()

def send_packet(ptype, payload):
    global sock
    data = struct.pack("<HB", len(payload) + 3, ptype) + payload
    sock.sendall(data)
    msg = ct(f"[SEND {ptype}] {decode_send(ptype, payload)}", pc(ptype))
    print(msg)
    return msg

def recvall(n):
    d = b""
    while len(d) < n:
        p = sock.recv(n - len(d))
        if not p: raise ConnectionError
        d += p
    return d

def recv_loop():
    global rcon_active, ping_time
    while True:
        try:
            h = recvall(3)
            length, ptype = struct.unpack("<HB", h)
            pl = recvall(length - 3)

            if ptype == SERVER_RCON:
                text = replace_nonprintables(pl[1:].decode(errors='ignore'))
                log_admin.append((ptype, pl))
                rcon_active = False

            elif ptype == SERVER_CONSOLE:
                log_admin.append((ptype, pl))  # jen do logu, nezobrazujeme

            elif ptype == SERVER_TEXT and len(pl) >= 3:
                origin, color = pl[0], struct.unpack_from("<H", pl, 1)[0]
                msg = replace_nonprintables(pl[3:].decode(errors='ignore'))
                src = {0: "SERVER", 1: "CLIENT", 13: "CONSOLE"}.get(origin, f"ORIGIN={origin}")
                print(ct(f"[120] ({src}) {msg}", pc(color)))

            elif ptype == SERVER_PONG and len(pl) == 4:
                val = struct.unpack("<I", pl)[0]
                rtt = int((time.time() - ping_time) * 1000) if ping_time else -1
                ts = datetime.fromtimestamp(val, timezone.utc) + timedelta(hours=2)
                tstr = ts.strftime("%d.%m.%Y %H:%M:%S")
                col = "\033[32m" if rtt < 100 else "\033[33m" if rtt < 200 else "\033[31m"
                print(ct(f"[126] PONG: {val} ({tstr}, {col}RTT {rtt} ms)", pc(126)))
                ping_time = None

            elif ptype in (107, 121):
                log_admin.append((ptype, pl))

            else:
                msg = ct(f"[{ptype}] {replace_nonprintables(pl.decode(errors='ignore'))}", pc(ptype))
                print(msg)
        except Exception as e:
            print(f"[ERROR] {e}")
            break

def main():
    global sock, rcon_active, ping_time
    sock = socket.create_connection((host, port), timeout=10)
    print("CONNECTED")
    threading.Thread(target=recv_loop, daemon=True).start()

    send_packet(ADMIN_JOIN, password.encode()+b'\0TestBot\0v1.0\0')
    time.sleep(1)
    for ut,f in {0:FREQ_DAILY,1:FREQ_AUTOMATIC,2:FREQ_AUTOMATIC,3:FREQ_POLL,4:FREQ_POLL,5:FREQ_AUTOMATIC,6:FREQ_AUTOMATIC,8:FREQ_AUTOMATIC}.items():
        send_packet(ADMIN_UPDATE_FREQUENCY, struct.pack("<HBH", ut,f,0))
    send_packet(ADMIN_UPDATE_FREQUENCY, struct.pack("<HBH",7,FREQ_POLL,0))

    while True:
        print("\nMENU: 1=log 2=rcon 3=ping 4=companyinfo 5=clientinfo 6=chat 7=quit")
        cmd = input("> ").strip()
        if cmd == "1":
            print("----- ADMIN LOG -----")
            for e in log_admin: print(e)
            input("Enter →")
        elif cmd == "2":
            rcon_active = True
            val = input("RCON command: ") + "\0"
            send_packet(ADMIN_RCON, val.encode())
            while rcon_active: time.sleep(0.05)
        elif cmd == "3":
            ping_time = time.time()
            timestamp = int(ping_time)
            send_packet(ADMIN_PING, struct.pack("<I", timestamp))
        elif cmd in ("4", "5"):
            cmd_str = "company info\0" if cmd=="4" else "client info\0"
            rcon_active = True
            send_packet(ADMIN_RCON, cmd_str.encode())
            while rcon_active: time.sleep(0.05)
        elif cmd == "6":
            msg = input("Chat message: ")
            admin_id = 1
            dest_type = 2  # všem
            dest_id = 0
            payload = struct.pack("<IBI", admin_id, dest_type, dest_id) + msg.encode() + b'\0'
            send_packet(ADMIN_CHAT, payload)
        elif cmd == "7":
            break

if __name__ == "__main__":
    main()
