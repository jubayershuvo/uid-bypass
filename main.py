# ==================== CONFIGURATION ====================
import json
import os
import time
from mitmproxy import http
from lib.res_extractor import decode_hex_payload
from lib.decode_jwt import decode_jwt
from lib.req_modifier import modify_hex
from typing import Tuple, List, Any, Dict

# ==================== LOG SETUP ====================
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

REQ_OUTPUT_FILE = os.path.join(LOG_DIR, "original_hex.txt")
MOD_REQ_OUTPUT_FILE = os.path.join(LOG_DIR, "modified_hex.txt")
RESP_OUTPUT_FILE = os.path.join(LOG_DIR, "response_hex.txt")
JSON_RESP_OUTPUT_FILE = os.path.join(LOG_DIR, "response_json.json")
REQ_HEADERS_OUTPUT_FILE = os.path.join(LOG_DIR, "request_headers.txt")
BLOCKED_LOG_FILE = os.path.join(LOG_DIR, "blocked_events.txt")

# ==================== ANTI-CHEAT BYPASS ADDON ====================
class AntiCheatBypass:
    """
    Anti-Cheat Bypass - Changes targeted keys to real mobile values
    """
    
    def __init__(self):
        self.blocked_count = 0
        self.modified_count = 0
        self.TARGET_PATH = "/LogEvent"
        
        # TARGETED KEYS WITH REAL MOBILE VALUES (from phone logs)
        self.target_values = {
            # CPU
            "cpu_hardware": "ARM64 FP ASIMD AES | 2000 | 8",
            
            # GPU
            "gl_render": "Mali-G52 MC2",
            "gl_version": "OpenGL ES 3.2 v1.r32p1-01eac0.2a893c04ca0026c2e6802dbe7d7af5c5",
            
            # Display
            "screen_width": 1600,
            "screen_hight": 720,
            "screen_height": 720,
            "detection":[15,138,171,173,227,353,1217,3004],

            # Flags
            "is_emulator": False,
        }
        
        # FFAnti pipe format targeted keys with real mobile values
        self.ffanti_values = {
            "x86": "0",
            "root": "0",
            "adb": "0",
        }
        
        # Block id=8
        self.block_id8 = True
    
    def _is_target_event(self, flow) -> bool:
        """Check if this is a LogEvent POST request"""
        return (flow.request.path.endswith(self.TARGET_PATH) and 
                flow.request.method == "POST")
    
    def _send_empty_response(self, flow):
        """Send empty 200 OK to block the request"""
        self.blocked_count += 1
        flow.response = http.Response.make(200, b'', {"Content-Type": "application/json"})
    
    def _log(self, action: str, flow, event_type: str, reason: str, changed: list = None):
        """Log actions"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        count = self.blocked_count if action == "BLOCKED" else self.modified_count
        
        print(f"\n{'='*50}")
        print(f"{'🚫' if action == 'BLOCKED' else '✏️'} [{action}] #{count}")
        print(f"   Event: {event_type}")
        print(f"   Reason: {reason}")
        if changed:
            print(f"   Changed: {', '.join(changed)}")
        print(f"   Time: {timestamp}")
        print(f"{'='*50}")
        
        with open(BLOCKED_LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {action} #{count}\n")
            f.write(f"Event: {event_type}\nReason: {reason}\n")
            if changed:
                f.write(f"Changed: {', '.join(changed)}\n")
            f.write("-" * 50 + "\n")
    
    def _fix_pipe_format(self, text: str) -> Tuple[bool, str, list]:
        """Fix pipe-separated format (FFAnti info field)"""
        if '|' not in text or '=' not in text:
            return (False, text, [])
        
        modified = False
        changed = []
        parts = text.split('|')
        fixed_parts = []
        
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                
                # Remove null bytes for comparison
                clean_value = value.replace('\x00', '')
                
                # Change targeted keys to mobile values
                if key in self.ffanti_values:
                    new_value = str(self.ffanti_values[key])
                    if clean_value != new_value:
                        modified = True
                        changed.append(f"{key}: {value} -> {new_value}")
                        fixed_parts.append(f"{key}={new_value}")
                    else:
                        fixed_parts.append(part)
                else:
                    fixed_parts.append(part)
            else:
                fixed_parts.append(part)
        
        return (modified, '|'.join(fixed_parts), changed)
    
    def _fix_json_payload(self, obj: Any, depth: int = 0) -> Tuple[bool, Any, list]:
        """Recursively fix JSON payload by changing targeted keys"""
        if depth > 15:  # Increased depth limit
            return (False, obj, [])
        
        modified = False
        changed = []
        
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                # Change targeted keys to mobile values
                if key in self.target_values:
                    new_value = self.target_values[key]
                    old_value = obj[key]
                    
                    # Handle type conversion (int vs string)
                    if isinstance(new_value, int) and isinstance(old_value, str):
                        try:
                            old_value = int(float(old_value))
                        except:
                            pass
                    
                    if old_value != new_value:
                        changed.append(f"{key}: {obj[key]} -> {new_value}")
                        obj[key] = new_value
                        modified = True
                
                # Handle nested objects
                elif isinstance(obj[key], (dict, list)):
                    sub_modified, obj[key], sub_changed = self._fix_json_payload(obj[key], depth + 1)
                    if sub_modified:
                        modified = True
                        changed.extend(sub_changed)
                
                # Handle pipe format in string values
                elif isinstance(obj[key], str) and '|' in obj[key] and '=' in obj[key]:
                    sub_modified, obj[key], sub_changed = self._fix_pipe_format(obj[key])
                    if sub_modified:
                        modified = True
                        changed.extend(sub_changed)
        
        elif isinstance(obj, list):
            for i in range(len(obj)):
                sub_modified, obj[i], sub_changed = self._fix_json_payload(obj[i], depth + 1)
                if sub_modified:
                    modified = True
                    changed.extend(sub_changed)
        
        return (modified, obj, changed)
    
    def _safe_json_parse(self, text: str) -> Tuple[bool, Any]:
        """Safely parse JSON with error handling"""
        try:
            return (True, json.loads(text))
        except json.JSONDecodeError:
            return (False, text)
    
    def request(self, flow):
        """Main request handler"""
        if not self._is_target_event(flow):
            return
        
        try:
            # Get request body as string
            body = flow.request.get_text()
            data = json.loads(body)
            event_type = data.get("event_type", "")
            event_payload = data.get("event_payload", "")
            
            # BLOCK id=8 in FFAnti
            if self.block_id8 and event_type == "EventTypeFFAnti":
                # Check in both string and parsed forms
                payload_str = str(event_payload)
                if "id=8" in payload_str:
                    self._log("BLOCKED", flow, event_type, "id=8 detected (emulator)")
                    self._send_empty_response(flow)
                    return
                
                # Also check parsed info field
                if isinstance(event_payload, dict):
                    info = event_payload.get("info", "")
                    if "id=8" in str(info):
                        self._log("BLOCKED", flow, event_type, "id=8 detected in info field (emulator)")
                        self._send_empty_response(flow)
                        return
            
            # Process event_payload
            modified = False
            all_changed = []
            
            # Handle event_payload as string (nested JSON)
            if isinstance(event_payload, str):
                # Try to parse as JSON first
                is_json, parsed = self._safe_json_parse(event_payload)
                
                if is_json:
                    # It's a JSON string, fix the parsed object
                    sub_modified, fixed, changed = self._fix_json_payload(parsed)
                    if sub_modified:
                        # Re-serialize to string
                        data["event_payload"] = json.dumps(fixed, separators=(',', ':'))
                        modified = True
                        all_changed.extend(changed)
                else:
                    # Not JSON, try pipe format
                    sub_modified, fixed, changed = self._fix_pipe_format(event_payload)
                    if sub_modified:
                        data["event_payload"] = fixed
                        modified = True
                        all_changed.extend(changed)
            
            elif isinstance(event_payload, dict):
                # event_payload is already a dict
                sub_modified, fixed, changed = self._fix_json_payload(event_payload)
                if sub_modified:
                    data["event_payload"] = fixed
                    modified = True
                    all_changed.extend(changed)
            
            # Also fix top-level keys
            sub_modified, data, changed = self._fix_json_payload(data)
            if sub_modified:
                modified = True
                all_changed.extend(changed)
            
            # Apply modifications if any
            if modified:
                # Serialize with no extra spaces to preserve original format
                new_body = json.dumps(data, separators=(',', ':'))
                flow.request.text = new_body
                
                # CRITICAL: Update Content-Length header
                flow.request.headers["Content-Length"] = str(len(new_body.encode('utf-8')))
                
                self.modified_count += 1
                self._log("MODIFIED", flow, event_type, "Changed targeted keys to mobile values", all_changed)
            
            # Allow all other requests to pass through
            
        except json.JSONDecodeError as e:
            print(f"JSON Decode Error: {e}")
            pass
        except Exception as e:
            print(f"Error in AntiCheatBypass: {e}")
            import traceback
            traceback.print_exc()
            pass

# ==================== MAJOR LOGIN CAPTURE ADDON ====================
class MajorLoginCapture:
    def __init__(self):
        self.target_path = "/MajorLogin"
        self.request_count = 0

    def _match(self, flow) -> bool:
        """Check if this is a /MajorLogin request"""
        return (
            flow.request.method == "POST"
            and flow.request.path.startswith(self.target_path)
        )

    def request(self, flow):
        """Handle MajorLogin requests"""
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

    def response(self, flow):
        """Handle MajorLogin responses"""
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
                    f.write(f"=== RESPONSE #{self.request_count} ===\n")
                    f.write(json.dumps(json_data, indent=2))
                    f.write("\n\n")
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


# ==================== BOTH ADDONS ====================
addons = [
    AntiCheatBypass(),    # Blocks anti-cheat events
    MajorLoginCapture()   # Captures and modifies MajorLogin
]