# ==================== CONFIGURATION ====================
import json
import os
import time
from lib.res_extractor import decode_hex_payload
from lib.decode_jwt import decode_jwt
from lib.req_modifier import modify_hex

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

REQ_OUTPUT_FILE = os.path.join(LOG_DIR, "original_hex.txt")
MOD_REQ_OUTPUT_FILE = os.path.join(LOG_DIR, "modified_hex.txt")
RESP_OUTPUT_FILE = os.path.join(LOG_DIR, "response_hex.txt")
JSON_RESP_OUTPUT_FILE = os.path.join(LOG_DIR, "response_json.json")
REQ_HEADERS_OUTPUT_FILE = os.path.join(LOG_DIR, "request_headers.txt")
BLOCKED_LOG_FILE = os.path.join(LOG_DIR, "blocked_events.txt")

# Anti-cheat bypass configuration
BLOCKED_EVENTS = ["EventTypeFFAnti", "EventTypeEnterGame"]
ANTI_CHEAT_ENDPOINT = "/LogEvent"  # Match any host with this path


class MajorLoginCapture:
    def __init__(self):
        self.target_path = "/MajorLogin"
        self.request_count = 0
        self.blocked_count = 0

    def _is_anti_cheat_event(self, flow) -> bool:
        """Check if this is an anti-cheat event to block"""
        # Check if path ends with or matches ANTI_CHEAT_ENDPOINT
        if not flow.request.path.endswith(ANTI_CHEAT_ENDPOINT):
            return False
        if flow.request.method != "POST":
            return False
        
        try:
            body = flow.request.text
            data = json.loads(body)
            event_type = data.get("event_type", "")
            return event_type in BLOCKED_EVENTS
        except:
            return False
    
    def _block_anti_cheat(self, flow):
        """Return 200 OK for blocked events"""
        self.blocked_count += 1
        event_type = "Unknown"
        event_payload = ""
        
        try:
            data = json.loads(flow.request.text)
            event_type = data.get("event_type", "Unknown")
            event_payload = data.get("event_payload", "")
        except:
            pass
        
        print("\n" + "=" * 50)
        print(f"🚫 [ANTI-CHEAT BYPASS] Blocked #{self.blocked_count}")
        print(f"   Host: {flow.request.pretty_host}")
        print(f"   Path: {flow.request.path}")
        print(f"   Event Type: {event_type}")
        print(f"   Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        # Log blocked events for analysis
        with open(BLOCKED_LOG_FILE, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] #{self.blocked_count}\n")
            f.write(f"Host: {flow.request.pretty_host}\n")
            f.write(f"Path: {flow.request.path}\n")
            f.write(f"Event: {event_type}\n")
            f.write(f"Payload: {event_payload}\n")
            f.write("-" * 50 + "\n")
        
        # Return 200 OK without forwarding to server
        flow.response = flow.response.make(
            200,
            b'{"code":200,"message":"OK"}',
            {"Content-Type": "application/json"}
        )
        return True

    def _match(self, flow) -> bool:
        """Check if this is a /MajorLogin request"""
        return (
            flow.request.method == "POST"
            and flow.request.path.startswith(self.target_path)
        )

    # ==================== REQUEST ====================
    def request(self, flow):
        # First, check if this is an anti-cheat event to block
        if self._is_anti_cheat_event(flow):
            self._block_anti_cheat(flow)
            return
        
        # Then handle MajorLogin requests
        if not self._match(flow):
            return

        self.request_count += 1

        try:
            # Get original hex
            hex_data = flow.request.content.hex()
            
            # Save original request hex
            with open(REQ_OUTPUT_FILE, "a") as f:
                f.write(f"=== REQUEST #{self.request_count} ===\n")
                f.write(hex_data + "\n\n")

            print("\n" + "=" * 50)
            print(f"📤 MAJOR LOGIN REQUEST #{self.request_count}")
            print("=" * 50)
            print(f"📦 Length: {len(hex_data)} chars")
            print(f"📝 Preview: {hex_data[:100]}...")

            # Modify hex
            mod_hex = modify_hex(hex_data)

            if mod_hex == hex_data:
                print("❌ No modifications applied")
            else:
                print("✅ Modifications applied")
                print(f"🔧 Modified Length: {len(mod_hex)} chars")
                print(f"🔧 Modified Preview: {mod_hex[:100]}...")
                
                # Apply modified request
                flow.request.content = bytes.fromhex(mod_hex)

            # Save modified request hex
            with open(MOD_REQ_OUTPUT_FILE, "a") as f:
                f.write(f"=== REQUEST #{self.request_count} (MODIFIED) ===\n")
                f.write(mod_hex + "\n\n")

            # Save headers
            headers_dict = dict(flow.request.headers)
            with open(REQ_HEADERS_OUTPUT_FILE, "a") as f:
                f.write(f"=== REQUEST #{self.request_count} ===\n")
                f.write(json.dumps(headers_dict, indent=2))
                f.write("\n\n")

            print(f"✅ Request saved → {REQ_OUTPUT_FILE}")
            print(f"✅ Modified request saved → {MOD_REQ_OUTPUT_FILE}")

        except Exception as e:
            print(f"❌ Request error: {e}")
            import traceback
            traceback.print_exc()

    # ==================== RESPONSE ====================
    def response(self, flow):
        # Skip if this is a blocked event (already returned 200)
        if self._is_anti_cheat_event(flow):
            return
            
        if not self._match(flow):
            return

        try:
            resp_hex = flow.response.content.hex()
            
            print("\n" + "=" * 50)
            print(f"📥 MAJOR LOGIN RESPONSE")
            print("=" * 50)
            print(f"📦 Response Length: {len(resp_hex)} chars")

            result = decode_hex_payload(resp_hex)
            
            # Try to extract and decode JWT
            if 'strings' in result and len(result['strings']) > 1:
                base64 = result['strings'][1]
                json_data = decode_jwt(base64)
                
                # Save JSON response
                with open(JSON_RESP_OUTPUT_FILE, "a") as f:
                    f.write(json.dumps(json_data, indent=2))
                    f.write(",\n\n")
                print(f"✅ JWT decoded and saved → {JSON_RESP_OUTPUT_FILE}")
                
                # Print summary of decoded JWT
                if 'nickname' in json_data:
                    print(f"👤 Nickname: {json_data.get('nickname')}")
                if 'account_id' in json_data:
                    print(f"🆔 Account ID: {json_data.get('account_id')}")
            
            # Save response hex
            with open(RESP_OUTPUT_FILE, "a") as f:
                f.write(f"=== RESPONSE #{self.request_count} ===\n")
                f.write(resp_hex + "\n\n")
            
            print(f"✅ Response hex saved → {RESP_OUTPUT_FILE}")

        except Exception as e:
            print(f"❌ Response error: {e}")
            import traceback
            traceback.print_exc()


# ==================== ADDON ====================
addons = [MajorLoginCapture()]