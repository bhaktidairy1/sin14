import socket
import threading
import time
import binascii
import requests
from urllib.parse import urlparse
import re
# ─── keep‑alive webserver ────────────────────────────────────────────────────────
from flask import Flask, request
import threading
from collections import deque

# in‑memory log buffer
log_buffer = deque(maxlen=100)

# money count variable
global_money = 0

app = Flask(__name__)

@app.route('/')
def home():
    # display current money count and last 100 log lines
    return "<h1>Kit Money: {:,}</h1><pre>{}</pre>".format(
        global_money,
        "\n".join(log_buffer)
    )

@app.route('/log', methods=['POST'])
def log_endpoint():
    msg = request.get_data(as_text=True)
    log_buffer.append(msg)
    return 'OK', 200

def run_web():
    app.run(host='0.0.0.0', port=10000)

def keep_alive():
    t = threading.Thread(target=run_web)
    t.daemon = True
    t.start()

HOST = "202.239.51.41"
PORTS = [30001, 30002, 30003, 30004, 30005]


CURRENT_COORDS = "00060101" + "55003800"

# === LOGIN TOKEN HANDLING ===
session = requests.Session()
mageurl = (
    "https://gae4php82-real.an.r.appspot.com/_ah/login?continue=https://gae4php82-real.an.r.appspot.com/authcreate&auth=g.a000ywitBIOzJ9x5UpMzqadLmT_bRqbWUocG-8WbtpqkC9gwHbJxbvDaE9pvH1pvCnwdG1zHFQACgYKAe0SARISFQHGX2Miqq6GlB1F9OtvMwDzZbCg4xoVAUF8yKoCGgAU8I4kxj7Wu24b3p7A0076",)
session.get(mageurl, allow_redirects=True)
base = f"{urlparse(mageurl).scheme}://{urlparse(mageurl).netloc}"
resp_login_token = session.get(f"{base}/authcreate")
login_token = resp_login_token.text.strip()
LOGIN_TOKEN_HEX = login_token.encode().hex()
print("[+] Token:", LOGIN_TOKEN_HEX)
def log(msg: str):
    """Print + send to web‑log."""
    print(msg)
    try:
        requests.post("http://localhost:10000/log", data=msg)
    except:
        pass
def drain_socket(sock, total_timeout=3.5, read_timeout=1.0):
    """
    Drains all data from the socket, even if packets are delayed.
    - total_timeout: how long to wait for ALL delayed packets (e.g., 3.5s)
    - read_timeout: how long to wait per recv (e.g., 1.0s max between packets)
    """
    sock.settimeout(read_timeout)
    end_time = time.time() + total_timeout

    try:
        while time.time() < end_time:
            try:
                leftover = sock.recv(4096)
                if leftover:
                    continue  # got data, keep draining
                else:
                    break  # connection closed
            except socket.timeout:
                break  # waited 1s, nothing more came
    finally:
        sock.settimeout(None)  # restore default blocking mode

def hex_recv(sock, expect_len=4096, label=None) -> bytes:
    data = sock.recv(expect_len)
    if not data:
        raise ConnectionError("Server closed connection")
    h = binascii.hexlify(data).decode()
    print(f"← {label or 'Received'} ({len(data)}B): {h}")
    return data

# Special hex_recv for Map Data that updates money_count
def hex_recv_map_data(sock, expect_len=4096) -> bytes:
    global global_money
    data = sock.recv(expect_len)
    if not data:
        raise ConnectionError("Server closed connection")
    h = binascii.hexlify(data).decode()
    print(f"← MONEY IS HERE ({len(data)}B): {h}")

    # use provided find_hex_number logic
    identifier = "060162"
    # Find first occurrence
    first_pos = h.find(identifier)
    # Find second occurrence by starting search after first occurrence
    pos = h.find(identifier, first_pos + 1)
    print("FOUND SOME POS",pos)
    if pos != -1:
        # Move forward 74 characters from the START of second identifier
        target_pos = pos + 70
        print("So we FOUND FROM", h[pos:pos+84])
        # Extract 8 characters from that position
        hex_number = h[target_pos:target_pos+8]
        try:
            global_money = int(hex_number, 16)
            log(f"[+] Updated money_count: {global_money}")
        except ValueError:
            pass
    return data


def hex_send(sock, hexstr: str, label=None):
    raw = binascii.unhexlify(hexstr)
    sock.sendall(raw)
    print(f"→ {label or 'Sent'}: {hexstr}")


def hex_recv_NOPRINT(sock, expect_len=4096, label=None) -> bytes:
    data = sock.recv(expect_len)
    if not data:
        raise ConnectionError("Server closed connection")
    #h = binascii.hexlify(data).decode()
    #print(f"← {label or 'Received'} ({len(data)}B): {h}")
    return data


def hex_send_NOPRINT(sock, hexstr: str, label=None):
    raw = binascii.unhexlify(hexstr)
    sock.sendall(raw)
    #print(f"→ {label or 'Sent'}: {hexstr}")
    

def get_inventory_items(sock) -> dict:
    """
    Sends inventory request, then ALWAYS does a Buy‑25‑dangos to
    get the freshest inventory blob. Parses and returns the item dict.
    """
    # 1) Ask for inventory
    hex_send(sock, "00020120", "Inventory")
    inv_blob = hex_recv(sock, label="Current Inventory")

    # 2) Regardless, buy 25 dangos and parse *that* blob
    hex_send(sock, "000b2100000000010000243e19", "Buy 25 dangos")
    buy_blob = hex_recv(sock, label="Buy 25 dangos")

    # 3) Check if buy_blob has relevant item prefixes
    prefixes = ["243e", "2ac6", "2ac7", "0fcf"]
    buy_hex = buy_blob.hex()
    if any(p in buy_hex for p in prefixes):
        data = buy_blob
        log("[+] Using buy_blob for inventory.")
    else:
        data = inv_blob
        log("[+] Using inv_blob for inventory fallback.")

    # 4) Extract items
    prefix_to_key = {
        "243e": "dango",
        "2ac6": "fur",
        "2ac7": "claw",
        "0fcf": "sword",
    }
    itemList = {name: {"id": None, "qty": 0} for name in prefix_to_key.values()}
    results = extract_multiple_items_info(data, list(prefix_to_key.keys()))
    for prefix, item_id, qty in results:
        key = prefix_to_key[prefix]
        if itemList[key]["id"] is None:
            itemList[key] = {"id": item_id, "qty": qty}

    return itemList



def cerbera_battle(s):
    try:
        # 1) Enter Boss Room
        hex_send_NOPRINT(s, "0003300601000f3002110000000300000000000099200003300600000e01100000995c00001b0000004800", "Enter Boss Room")
        hex_recv_NOPRINT(s, label="BossRoom-ACK")
        hex_recv_NOPRINT(s, label="BossRoom-Payload")

        # 3) Start Battle
        hex_send_NOPRINT(s, "0002013a000f30021100000000000000000000995c", "Start Cutscene")
        hex_recv_NOPRINT(s, label="Enter Cutscene-ACK")
        battle_payload = hex_recv_NOPRINT(s, label="BattleStart-Payload").hex()

        # parse boss_id
        #m = re.search(r"([0-9a-f]{8})003bf3a8", battle_payload)
        hex_send_NOPRINT(s, "0003300601000f30021100000006000000000000995c0003300600000e01100000997a0000640000004100", "Skip Cutscene")
        hex_recv_NOPRINT(s, label="Skip Cutscene ACK")

        hex_send_NOPRINT(s, "0002013a000f30021100000000000000000000997a", "Fetch BossID")
        hex_recv_NOPRINT(s, label="BossID-ACK")
        payload = hex_recv_NOPRINT(s, label="BossID-Payload").hex()
        m2 = re.search(r"000000120248([0-9a-f]{8})003bf3a8", payload)
        if m2:
            boss_id=m2.group(1)
            print(f"[+] Parsed boss_id (fallback): {boss_id}")
        else:
            print("[-] Couldn't find boss_id, skipping attack")
            raise SystemExit
        #time.sleep(0.1)   todo IS THIS SPEED UP FINE?
        # 4) Attack
        hex_send_NOPRINT(s,
            "000a01431b870102" + boss_id +
            "000e01484e210102" + boss_id +
            "000000b4", "Attack Boss"
        )
        hex_recv_NOPRINT(s, label="Attack-ACK")
        hex_recv_NOPRINT(s, label="Attack-Payload (Important)")
        # 4.5) Return
        hex_send_NOPRINT(s, "00060157" + boss_id, "Killed this boss")
        #hex_recv_NOPRINT(s, label="BossKilledspecific-ACK")

        # 4.5) Return
        hex_send_NOPRINT(s, "001bb3000000000000000000000000000000000000000000000000000000033006010003300600000e01100000995c00001b0000005200", "Boss Dying Cutscene")
        hex_recv_NOPRINT(s, label="Return-ACK")
#        hex_recv_NOPRINT(s, label="Return-Payload")

        # 5) Return
        hex_send_NOPRINT(s, "0002013a0003300601000f30021100000007000000000000995c0003300600", "Skip cutscene2")
        hex_recv_NOPRINT(s, label="Return-ACK")
        #hex_recv_NOPRINT(s, label="Return-Payload")


        # 5) some more bs
        hex_send_NOPRINT(s, "000e0110000099200000550000003800", "Return NormalMap")
        hex_recv_NOPRINT(s, label="Return-ACK")
        hex_recv_NOPRINT(s, label="Return-Payload")

        # 6) Return again
        hex_send_NOPRINT(s, "0002013a000f300211000000000000000000009920", "Final Return to Map")
        hex_recv_NOPRINT(s, label="Return-ACK")
        hex_recv_NOPRINT(s, label="Return-Payload")

        # hex_send(s, "0002013a000f300211000000000000000000009920", "Final Return to Map")
        # hex_recv_NOPRINT(s, label="Return-ACK")
        # hex_recv(s, label="Return-Payload")
        #print("[+] cerbera Battle complete!")

    except Exception as e:
        print("[!] cerbera Battle error:", e)
        raise SystemExit

def extract_multiple_items_info(data: bytes, item_prefixes: list[str]):
    """
    Extracts item info (prefix, name, quantity) for all given item prefixes in the data.
    - item_prefixes: list of hex strings like ['2ac6', '2ac7', '0fcf']
    """
    results = []
    item_prefix_bytes = [bytes.fromhex(prefix) for prefix in item_prefixes]

    offset = 0
    data_len = len(data)

    while offset < data_len - 8:  # ensure enough room for item+name+qty
        segment = data[offset:offset+2]
        if segment in item_prefix_bytes:
            try:
                name_bytes = data[offset+2:offset+6]     # 4 bytes
                qty_bytes = data[offset+6:offset+8]      # 2 bytes

                name_hex = name_bytes.hex()
                quantity = int.from_bytes(qty_bytes, 'big')
                prefix_hex = segment.hex()

                results.append((prefix_hex, name_hex, quantity))
            except IndexError:
                break  # incomplete data
        offset += 1

    return results


def main(port):
    try:
        keep_alive()
        token_with_prefix = "0020" + LOGIN_TOKEN_HEX + "0000"
    
        # 1) Open TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        print(f"[+] Connecting to {HOST}:{port} …")
        s.connect((HOST, port))
        print("[+] Connected.\n")
    
        # 2) Send “0002fff3” (Init Packet)
        hex_send(s, "0002fff3", "Init Packet")
        #    → server replies the init header
        hex_recv(s, label="Init Header")
    
        # 3) Send dynamic‐length login: [length][FF02][0020<token>0000]
        raw_token = binascii.unhexlify(token_with_prefix)
        payload = b"\xFF\x02" + raw_token
        login_packet = len(payload).to_bytes(2, "big") + payload
        s.sendall(login_packet)
        print(f"→ Login Packet: {binascii.hexlify(login_packet).decode()}")
    
        #  → server should reply first with “00000003ff0200”
        data = hex_recv(s, label="Login ACK")
        h = binascii.hexlify(data).decode()
        if not h.startswith("00000003ff0200"):
            print("[-] Unexpected login response:", h)
            s.close()
            return
        print("[+] Login OK.\n")
    
        #  → immediately after “00000003ff0200” comes the ff03 (+ char-info) packet
        try:
            s.settimeout(0.3)
            extra = hex_recv(s, label="ff03 + char info")
            hexed = binascii.hexlify(extra).decode()
            idx = hexed.find("ff030100000001")
            if idx != -1 and len(hexed) >= idx + 14 + 8:
                char_id_hex = hexed[idx + 14 : idx + 14 + 8]
                print(f"[+] Parsed char_id_hex: {char_id_hex}\n")
            else:
                print("[-] Couldn't locate char_id_hex in the ff03 packet.")
                s.close()
                return
        except socket.timeout:
            print("[-] Timeout waiting for ff03.")
            s.close()
            return
        finally:
            s.settimeout(5.0)
    
        # ─────────── From here on: replay the “correct” Character/World sequence ───────────
        def send_and_log(pkt_hex, label=None, delay=0.1):
            hex_send(s, pkt_hex, label=label)
            time.sleep(delay)
    
        # 4) Character Select
        send_and_log("0002f032", "Character Select")
        #    → server: “0000009df032…” (character info)
        hex_recv(s, label="Character Info")
    
        # 5) Enter World #1: “00060001” + <char_id_hex>
        send_and_log("00060001", "Enter World")
        send_and_log(char_id_hex, "Character ID")
    
        #    money
        hex_recv_map_data(s)
    
        # 6) Post‐Map: “000623f3” + <char_id_hex>
        send_and_log("000623f3", "Post-Map")
        send_and_log(char_id_hex, "Character ID Repeat")
    
        #   money again
        hex_recv_map_data(s)
    
        # 7) Four movement‐handshake packets + “00026002”
        for step in ["00023300", "00023303", "00023300", "00023303"]:
            send_and_log(step, "Movement Step")
        send_and_log("00026002", "Movement Step")
    
        #    → server: movement sync
        hex_recv(s, label="Movement Sync")
    
        # 8) Presence start: “001bb300” + 24 zeros
        send_and_log("001bb300", "Presence Start")
        send_and_log("00000000000000000000000000000000000000000000000000", "Zeroes")
    
        # 9) Begin Sync: “0002013a” then “000e0110000318940000320000001000”
        send_and_log("0002013a", "Begin Sync")
        send_and_log("000e0110000099200000550000003800", "Position Data")         # MAP OF CERBERUS
        #    → server: ack for position
        hex_recv(s, label="Ack for Position")
    
        # 10) Resend Position: “0002013a”
        send_and_log("0002013a", "Resend Position")
        #    → server: extra state data
        hex_recv(s, label="Extra State Data")
    
        # 11) Bulk Action: “000f3002”
        send_and_log("000f3002", "Bulk Action")
        send_and_log("1100000000000000000000992000023209", "Bulk Action Contd.")
    
        # 12) Trigger Motion: “00020160”
        send_and_log("00020160", "Trigger Motion")
        #    → server: motion ack
        hex_recv(s, label="Motion Ack")
    
        # 13) Visuals Setup: “00038404”
        send_and_log("00038404", "Visuals Setup")
        send_and_log("00", "Visual Padding")
        # there supposed to be a 00028100000281100002830000028200 in between here
        # 14) Presence Confirm: “00060202” + <char_id_hex>
        send_and_log("00060202" + char_id_hex, "Presence Confirm")
        #    → server: presence ack
        hex_recv(s, label="Presence Ack")
    
        # 15) World Tick: “00033006”
        send_and_log("00033006", "World Tick")
    
        # 16) Trigger Something: “01000f300211000000020000000000031894”
        send_and_log("01000f300211000000050000000000001554", "Trigger Something")
        #    → server: update
        hex_recv(s, label="Server Update")
    
        # 17) Char “idle + coords” right away:
        #     “00067110” + <char_id_hex> + coords packet
        send_and_log("00067110" + char_id_hex + CURRENT_COORDS, "Char Idle + Coords")

        send_and_log("0006a102" + "5ee720ad", "Summon Pet")    #for each sin TODO
        #    → server: update
        hex_recv(s, label="Summon Pet")
    
        print("\n[+] Game session established. Starting packet loop and GUI…\n")
        print("[+] Entering infinite cerbera Battle loop")
    
        # hex_send(s, "000b210100000001139ee75102", "Sell 2 fur")   000b2100000000010000243e14
        drain_socket(s)  # Clean buffer
        inventory = get_inventory_items(s)
    
    
        count = 89
        while True:
            count = count + 1
            if count % 4 == 0:
                try:
                    hex_send(s, "00060121" + inventory["dango"]["id"], "Eat Potion")
                    hex_recv(s, label="Potion-ACK")
                except:
                    hex_send(s, "00060121" + "6e28c680", "Emergency Eat Potion") #TODO change for specific sin
                    hex_recv(s, label="Potion-ACK")
            if count % 100 == 0:
                drain_socket(s)
                total_earned = 0
                inventory = get_inventory_items(s)
                # Fur
                fur_id = inventory["fur"]["id"]
                fur_qty = inventory["fur"]["qty"]
                if fur_qty > 0x7F:
                    fur_qty_hex = '7f'
                else:
                    fur_qty_hex = fur_qty.to_bytes(1, 'big').hex()

                # Claw
                claw_id = inventory["claw"]["id"]
                claw_qty = inventory["claw"]["qty"]
                if claw_qty > 0x7F:
                    claw_qty_hex = '7f'
                else:
                    claw_qty_hex = claw_qty.to_bytes(1, 'big').hex()

                sword_id = inventory["sword"]["id"]
    
                if fur_id:
                    hex_send(s, "000b210100000001" + fur_id + fur_qty_hex, "Sell Fur")
                    hex_recv(s, label="Sell fur -ACK Must be 3210100")
                    total_earned += 6300 * int(fur_qty_hex, 16)
    
                if claw_id:
                    hex_send(s, "000b210100000001" + claw_id + claw_qty_hex, "Sell Claw")
                    hex_recv(s, label="Sell claw -ACK Must be 3210100")
                    total_earned += 57000 * int(claw_qty_hex, 16)
    
                if sword_id:
                    hex_send(s, "000b210100000001" + sword_id + "01", "Sell Sword")
                    hex_recv(s, label="Sell sword -ACK Must be 3210100")
                    total_earned += 100000

    
                #already bought 25 dango
                global global_money
                global_money += total_earned
                global_money -= 62500
                log(f"Sold fur: {fur_qty_hex}  \n Sold claw: {claw_qty_hex} ")
                log(f"Current Dango Amount:  {inventory['dango']['qty']}  ")
                log(f"[+] Updated money_count from sales: {global_money}")
    
            cerbera_battle(s)
            print(f"Battle Number: {count}  Finished")
    finally:
        print(f"[i] Closing socket for port {port}")
        s.close()
        time.sleep(180)
    

if __name__ == "__main__":
    port_index = 0
    while True:
        try:
            main(PORTS[port_index])
        except SystemExit:
            print(f"[!] Switching to next port due to boss_id error.")
            port_index = (port_index + 1) % len(PORTS)
            time.sleep(2)  # Optional: wait before reconnecting
            continue
        except Exception as e:
            print(f"[!] Unexpected crash: {e}")
            break
