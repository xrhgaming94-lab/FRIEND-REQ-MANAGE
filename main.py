from flask import Flask, request, jsonify, send_from_directory, render_template_string
import sys
import jwt
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import RemoveFriend_Req_pb2
from byte import Encrypt_ID, encrypt_api
import binascii
import data_pb2
import uid_generator_pb2
import my_pb2
import output_pb2
from datetime import datetime
import json
import time
import urllib3
import warnings
import base64
import os
import httpx
import asyncio
import ssl
import aiohttp
from google.protobuf import json_format

# -----------------------------
# Security Warnings Disable
# -----------------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=UserWarning, message="Unverified HTTPS request")

app = Flask(__name__)

# -----------------------------
# Configuration
# -----------------------------
PLATFORM_MAP = {
    "3": {"name": "Facebook", "icon": "fab fa-facebook", "color": "#1877F2"},
    "4": {"name": "Guest", "icon": "fas fa-user", "color": "#6c757d"},
    "5": {"name": "VK", "icon": "fab fa-vk", "color": "#4C75A3"},
    "8": {"name": "Google", "icon": "fab fa-google", "color": "#DB4437"},
    "10": {"name": "Apple", "icon": "fab fa-apple", "color": "#000000"},
    "11": {"name": "Twitter/X", "icon": "fab fa-twitter", "color": "#1DA1F2"}
}

REGION_CONFIGS = {
    "ind": {
        "url": "https://client.ind.freefiremobile.com",
        "host": "client.ind.freefiremobile.com",
        "name": "INDIA"
    },
    "us": {
        "url": "https://client.us.freefiremobile.com",
        "host": "client.us.freefiremobile.com",
        "name": "USA/BRAZIL"
    },
    "default": {
        "url": "https://clientbp.ggpolarbear.com",
        "host": "clientbp.common.ggbluefox.com",
        "name": "INTERNATIONAL"
    }
}

# External API URLs
EAT_TOKEN_URL = "https://ticket.kiosgamer.co.id"
ACCESS_TO_JWT_URL = "https://star-jwt-gen.vercel.app/token?access_token={access_token}"
GUEST_TO_JWT_URL = "https://star-jwt-gen.vercel.app/token?uid={uid}&password={password}"

# Player Info Configuration
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)"

# -----------------------------
# AES Configuration
# -----------------------------
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def encrypt_message(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data_bytes, AES.block_size))

def encrypt_message_hex(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(pad(data_bytes, AES.block_size))
    return binascii.hexlify(encrypted).decode('utf-8')

# -----------------------------
# AES CBC Encryption for Player Info
# -----------------------------
def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES CBC encryption with PKCS7 padding for player info"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_data)

# -----------------------------
# Region-based URL Configuration
# -----------------------------
def get_base_url(server_name="IND"):
    """Get base URL for a server region"""
    if server_name and server_name.lower() in REGION_CONFIGS:
        return REGION_CONFIGS[server_name.lower()]["url"] + "/"
    return REGION_CONFIGS["default"]["url"] + "/"

def get_server_from_token(token):
    """Extract server region from JWT token"""
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        lock_region = decoded.get("lock_region", "IND")
        return lock_region.upper()
    except:
        return "IND"

# -----------------------------
# Retry Decorator
# -----------------------------
def retry_operation(max_retries=3, delay=1):
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        time.sleep(delay * (attempt + 1))
            
            if last_exception:
                return {
                    "success": False,
                    "status": "error",
                    "message": f"All {max_retries} attempts failed",
                    "error": str(last_exception)
                }
            return {
                "success": False,
                "status": "error", 
                "message": f"All {max_retries} attempts failed"
            }
        return wrapper
    return decorator

# -----------------------------
# Token Processing Functions
# -----------------------------
def process_eat_token(eat_token):
    """Convert EAT token to Access Token"""
    try:
        # First get EAT token from kiosgamer
        eat_response = requests.get(EAT_TOKEN_URL, verify=False, timeout=10)
        if eat_response.status_code != 200:
            return None, "Failed to get EAT token"
        
        # Then convert to access token
        access_url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
        access_response = requests.get(access_url, verify=False, timeout=10)
        
        if access_response.status_code != 200:
            return None, "Failed to convert EAT to Access token"
        
        # Try to extract access token
        try:
            data = access_response.json()
            access_token = data.get('access_token')
            if access_token:
                return access_token, None
        except:
            pass
        
        # Try to extract from text
        text = access_response.text
        if 'access_token' in text:
            # Try to parse access token from response
            import re
            match = re.search(r'access_token["\']?:\s*["\']([^"\']+)["\']', text)
            if match:
                return match.group(1), None
        
        return None, "Could not extract access token from response"
        
    except Exception as e:
        return None, f"EAT token processing error: {str(e)}"

def convert_to_jwt(token, token_type):
    """Convert various token types to JWT"""
    try:
        if token_type == 'token':
            # Already JWT token
            return token, None
            
        elif token_type == 'access_token':
            # Convert access token to JWT
            url = ACCESS_TO_JWT_URL.format(access_token=token)
            response = requests.get(url, verify=False, timeout=10)
            
            if response.status_code != 200:
                return None, f"Failed to convert access token to JWT: HTTP {response.status_code}"
            
            try:
                data = response.json()
                jwt_token = data.get('token')
                if jwt_token:
                    return jwt_token, None
                else:
                    return None, "No JWT token in response"
            except:
                # Try to extract from text
                text = response.text
                if 'token' in text:
                    import re
                    match = re.search(r'token["\']?:\s*["\']([^"\']+)["\']', text)
                    if match:
                        return match.group(1), None
                return None, "Invalid JSON response"
            
        elif token_type == 'eat_token':
            # Process EAT token
            access_token, error = process_eat_token(token)
            if error:
                return None, error
            
            # Convert to JWT
            return convert_to_jwt(access_token, 'access_token')
            
        elif token_type == 'uid_password':
            # Convert UID:Password to JWT
            if ':' not in token:
                return None, "Invalid format. Use UID:Password"
            
            uid, password = token.split(':', 1)
            uid = uid.strip()
            password = password.strip()
            
            url = GUEST_TO_JWT_URL.format(uid=uid, password=password)
            response = requests.get(url, verify=False, timeout=10)
            
            if response.status_code != 200:
                return None, f"Failed to convert UID:Password to JWT: HTTP {response.status_code}"
            
            try:
                data = response.json()
                jwt_token = data.get('token')
                if jwt_token:
                    return jwt_token, None
                else:
                    return None, "No JWT token in response"
            except:
                return None, "Invalid JSON response"
            
        else:
            return None, f"Unknown token type: {token_type}"
            
    except requests.exceptions.Timeout:
        return None, "Request timeout - server may be down"
    except requests.exceptions.ConnectionError:
        return None, "Connection error - check your internet"
    except Exception as e:
        return None, f"Token conversion error: {str(e)}"

def extract_user_info(jwt_token):
    """Extract user information from JWT token"""
    try:
        decoded = jwt.decode(jwt_token, options={"verify_signature": False})
        
        your_uid = decoded.get('account_id') or decoded.get('sub') or decoded.get('uid')
        nickname = decoded.get('nickname') or decoded.get('name') or "Unknown"
        region = decoded.get('lock_region') or decoded.get('region') or "IND"
        platform = decoded.get('external_type') or decoded.get('platform') or "4"
        
        # Get region name
        region_key = region.lower()
        region_name = REGION_CONFIGS.get(region_key, REGION_CONFIGS["default"])["name"]
        
        # Get platform name
        platform_name = PLATFORM_MAP.get(str(platform), {"name": f"Platform {platform}"})["name"]
        
        return {
            "success": True,
            "jwt_token": jwt_token,
            "your_uid": str(your_uid) if your_uid else "Unknown",
            "nickname": nickname,
            "region": region.upper(),
            "region_name": region_name,
            "platform": platform,
            "platform_name": platform_name,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to decode JWT: {str(e)}"
        }

# -----------------------------
# Player Info Functions
# -----------------------------
def create_info_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = int(uid)
    message.garena = 1
    return message.SerializeToString()

def get_player_info_sync(target_uid, token, server_name=None):
    """Get player information (synchronous version)"""
    try:
        if not server_name:
            server_name = get_server_from_token(token)
            
        protobuf_data = create_info_protobuf(target_uid)
        encrypted_data = encrypt_message_hex(protobuf_data)
        endpoint = get_base_url(server_name) + "GetPlayerPersonalShow"

        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB53"
        }

        response = requests.post(endpoint, data=bytes.fromhex(encrypted_data), headers=headers, verify=False, timeout=10)
        
        if response.status_code != 200:
            return None

        hex_response = response.content.hex()
        binary = bytes.fromhex(hex_response)
        
        info = data_pb2.AccountPersonalShowInfo()
        info.ParseFromString(binary)
        
        return info
    except Exception as e:
        print(f"Error getting player info: {e}")
        return None

async def get_player_info_async(uid: str, token: str):
    """Get player information using async method"""
    try:
        server_name = get_server_from_token(token)
        
        # Create request payload using uid_generator_pb2
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        
        # Serialize protobuf
        payload = message.SerializeToString()
        
        # Encrypt the payload
        encrypted_data = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
        
        # Prepare headers
        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'Authorization': f"Bearer {token}",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB53"
        }
        
        # Get endpoint URL based on server
        endpoint = get_base_url(server_name) + "GetPlayerPersonalShow"
        
        # Make the API call
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            resp = await client.post(endpoint, data=encrypted_data, headers=headers)
            
            if resp.status_code == 200 and len(resp.content) > 10:
                # Parse the protobuf response using data_pb2
                info = data_pb2.AccountPersonalShowInfo()
                info.ParseFromString(resp.content)
                
                # Convert to dictionary
                data = json_format.MessageToDict(info)
                
                # Add metadata
                data["_metadata"] = {
                    "status": "success",
                    "server": server_name,
                    "uid_requested": uid,
                    "timestamp": datetime.now().isoformat(),
                    "response_size": len(resp.content)
                }
                
                return data
            else:
                return {
                    "success": False,
                    "error": f"HTTP {resp.status_code}",
                    "status_code": resp.status_code,
                    "content_length": len(resp.content)
                }
    
    except ValueError as e:
        return {
            "success": False,
            "error": f"Invalid UID format: {e}",
            "uid": uid
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "type": type(e).__name__
        }

def convert_timestamps_to_dates(data):
    """Recursively convert Unix timestamps to readable dates"""
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            if any(time_key in key.lower() for time_key in ['time', 'at', 'expire', 'end', 'start', 'create', 'login']):
                if isinstance(value, (str, int)) and (isinstance(value, int) or value.isdigit()):
                    try:
                        timestamp = int(value)
                        if timestamp > 946684800:  # After 2000
                            result[key] = {
                                "timestamp": value,
                                "date": datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                                "readable": datetime.fromtimestamp(timestamp).strftime('%B %d, %Y at %I:%M:%S %p')
                            }
                        else:
                            result[key] = value
                    except (ValueError, TypeError):
                        result[key] = value
                else:
                    result[key] = convert_timestamps_to_dates(value)
            else:
                result[key] = convert_timestamps_to_dates(value)
        return result
    elif isinstance(data, list):
        return [convert_timestamps_to_dates(item) for item in data]
    else:
        return data

def extract_player_info(info_data):
    """Extract player information from protobuf response"""
    if not info_data:
        return None

    basic_info = info_data.basic_info
    return {
        'uid': basic_info.account_id,
        'nickname': basic_info.nickname,
        'level': basic_info.level,
        'region': basic_info.region,
        'likes': basic_info.liked,
        'release_version': basic_info.release_version,
        'total_matches': getattr(basic_info, 'total_matches', 0),
        'wins': getattr(basic_info, 'wins', 0),
        'rank': getattr(basic_info, 'rank', 0),
        'max_rank': getattr(basic_info, 'max_rank', 0),
        'cs_rank': getattr(basic_info, 'cs_rank', 0),
        'cs_max_rank': getattr(basic_info, 'cs_max_rank', 0)
    }

# -----------------------------
# Authentication API Endpoint
# -----------------------------
@app.route('/api/process-token', methods=['POST'])
def process_token():
    """Process different types of tokens and convert to JWT"""
    try:
        data = request.json
        token = data.get('token', '').strip()
        token_type = data.get('token_type', 'token')
        
        if not token:
            return jsonify({
                "success": False,
                "error": "No token provided"
            }), 400
        
        # Convert to JWT
        jwt_token, error = convert_to_jwt(token, token_type)
        if error:
            return jsonify({
                "success": False,
                "error": error
            }), 400
        
        # Extract user info
        user_info = extract_user_info(jwt_token)
        if not user_info["success"]:
            return jsonify(user_info), 400
        
        return jsonify(user_info)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

# -----------------------------
# Get Player Info API
# -----------------------------
@app.route('/api/get-player-info', methods=['GET'])
def get_player_info():
    """Get player information using user's token"""
    try:
        token = request.args.get('token')
        target_uid = request.args.get('uid')
        
        if not token:
            return jsonify({
                "success": False,
                "error": "Missing token"
            }), 400
        
        if not target_uid:
            return jsonify({
                "success": False,
                "error": "Missing target UID"
            }), 400
        
        # Validate token
        try:
            jwt.decode(token, options={"verify_signature": False})
        except:
            return jsonify({
                "success": False,
                "error": "Invalid JWT token"
            }), 400
        
        # Get player info using synchronous method
        info = get_player_info_sync(target_uid, token)
        
        if info:
            # Extract player info
            player_data = extract_player_info(info)
            
            if player_data:
                # Add timestamp
                player_data["success"] = True
                player_data["timestamp"] = datetime.now().isoformat()
                player_data["message"] = f"Successfully retrieved info for UID: {target_uid}"
                
                return jsonify(player_data)
            else:
                return jsonify({
                    "success": False,
                    "error": "Failed to extract player info"
                }), 400
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to get player info for UID: {target_uid}",
                "status_code": 404
            }), 404
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@app.route('/api/get-player-info-async', methods=['GET'])
async def get_player_info_async_endpoint():
    """Get player information using async method"""
    try:
        token = request.args.get('token')
        target_uid = request.args.get('uid')
        
        if not token:
            return jsonify({
                "success": False,
                "error": "Missing token"
            }), 400
        
        if not target_uid:
            return jsonify({
                "success": False,
                "error": "Missing target UID"
            }), 400
        
        # Validate token
        try:
            jwt.decode(token, options={"verify_signature": False})
        except:
            return jsonify({
                "success": False,
                "error": "Invalid JWT token"
            }), 400
        
        # Get player info using async method
        result = await get_player_info_async(target_uid, token)
        
        if result.get("success") is not False and "_metadata" in result:
            # Simplify the response for frontend
            simplified_result = {
                "success": True,
                "uid": target_uid,
                "server": result["_metadata"]["server"],
                "timestamp": result["_metadata"]["timestamp"],
                "data": result
            }
            return jsonify(simplified_result)
        else:
            return jsonify({
                "success": False,
                "error": result.get("error", "Unknown error"),
                "uid": target_uid
            }), 400
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

# -----------------------------
# Friend Management Functions
# -----------------------------
def decode_author_uid(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded.get("account_id") or decoded.get("sub")
    except:
        return None

@retry_operation(max_retries=3, delay=1)
def remove_friend_with_retry(author_uid, target_uid, token, server_name=None):
    """Remove friend with retry mechanism"""
    try:
        if not server_name:
            server_name = get_server_from_token(token)
            
        msg = RemoveFriend_Req_pb2.RemoveFriend()
        msg.AuthorUid = int(author_uid)
        msg.TargetUid = int(target_uid)
        encrypted_bytes = encrypt_message(msg.SerializeToString())

        url = get_base_url(server_name) + "RemoveFriend"
        headers = {
            'Authorization': f"Bearer {token}",
            'User-Agent': "Dalvik/2.1.0 (Linux; Android 9)",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB53"
        }

        res = requests.post(url, data=encrypted_bytes, headers=headers, verify=False, timeout=10)
        
        # Check response
        if res.status_code == 200:
            return {
                "success": True,
                "status": "success",
                "message": f"Successfully removed friend {target_uid}",
                "author_uid": author_uid,
                "target_uid": target_uid,
                "server": server_name,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        else:
            return {
                "success": False,
                "status": "failed",
                "message": f"Failed to remove friend: HTTP {res.status_code}",
                "author_uid": author_uid,
                "target_uid": target_uid,
                "server": server_name,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    except Exception as e:
        print(f"Remove friend error: {e}")
        raise e

@retry_operation(max_retries=3, delay=1)
def send_friend_request_with_retry(author_uid, target_uid, token, server_name=None):
    """Send friend request with retry mechanism"""
    try:
        if not server_name:
            server_name = get_server_from_token(token)
            
        encrypted_id = Encrypt_ID(target_uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)

        url = get_base_url(server_name) + "RequestAddingFriend"
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)"
        }

        r = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), verify=False, timeout=10)
        
        # Check response
        if r.status_code == 200:
            return {
                "success": True,
                "status": "success",
                "message": f"Friend request sent to {target_uid}",
                "author_uid": author_uid,
                "target_uid": target_uid,
                "server": server_name,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        else:
            return {
                "success": False,
                "status": "failed",
                "message": f"Failed to send friend request: HTTP {r.status_code}",
                "author_uid": author_uid,
                "target_uid": target_uid,
                "server": server_name,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        
    except Exception as e:
        print(f"Add friend error: {e}")
        raise e

# -----------------------------
# Get Friends List
# -----------------------------
def get_friends_list(token, server_name=None):
    """Get user's friends list"""
    try:
        if not server_name:
            server_name = get_server_from_token(token)
        
        # This is a placeholder - you need to implement the actual API call
        # based on Free Fire's friends list endpoint
        author_uid = decode_author_uid(token)
        
        # Extract user info
        user_info = extract_user_info(token)
        if not user_info["success"]:
            return user_info
        
        # For demonstration, return empty list
        return {
            "success": True,
            "total_friends": 0,
            "friends": [],
            "your_uid": user_info.get("your_uid", "Unknown"),
            "nickname": user_info.get("nickname", "Unknown"),
            "region": user_info.get("region", "IND"),
            "region_name": user_info.get("region_name", "INDIA"),
            "platform": user_info.get("platform", "4"),
            "platform_name": user_info.get("platform_name", "Guest"),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to get friends list: {str(e)}"
        }

# -----------------------------
# API Routes for Frontend
# -----------------------------
@app.route('/adding_friend', methods=['GET'])
def adding_friend():
    """Add friend endpoint"""
    token = request.args.get('token')
    friend_uid = request.args.get('friend_uid')
    
    if not token or not friend_uid:
        return jsonify({
            "success": False,
            "error": "Missing token or friend_uid"
        }), 400
    
    author_uid = decode_author_uid(token)
    if not author_uid:
        return jsonify({
            "success": False,
            "error": "Invalid token"
        }), 400
    
    result = send_friend_request_with_retry(author_uid, friend_uid, token)
    return jsonify(result)

@app.route('/remove_friend', methods=['GET'])
def remove_friend():
    """Remove friend endpoint"""
    token = request.args.get('token')
    friend_uid = request.args.get('friend_uid')
    
    if not token or not friend_uid:
        return jsonify({
            "success": False,
            "error": "Missing token or friend_uid"
        }), 400
    
    author_uid = decode_author_uid(token)
    if not author_uid:
        return jsonify({
            "success": False,
            "error": "Invalid token"
        }), 400
    
    result = remove_friend_with_retry(author_uid, friend_uid, token)
    return jsonify(result)

@app.route('/get_friends_list', methods=['GET'])
def get_friends():
    """Get friends list endpoint"""
    token = request.args.get('token')
    
    if not token:
        return jsonify({
            "success": False,
            "error": "Missing token"
        }), 400
    
    result = get_friends_list(token)
    return jsonify(result)

# -----------------------------
# Serve HTML Files
# -----------------------------
@app.route('/')
def serve_index():
    """Serve the main HTML file"""
    # Read the HTML file
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return html_content
    except FileNotFoundError:
        return "index.html not found. Make sure it's in the same directory as app.py", 404

@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files (CSS, JS, etc.)"""
    # For now, just serve HTML if requested
    if filename == 'index.html':
        return serve_index()
    return f"File {filename} not found", 404

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy", 
        "service": "FreeFire Friend Manager",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "endpoints": {
            "POST /api/process-token": "Process tokens to JWT",
            "GET /api/get-player-info": "Get player information",
            "GET /api/get-player-info-async": "Get player info (async)",
            "GET /adding_friend": "Send friend request",
            "GET /remove_friend": "Remove friend",
            "GET /get_friends_list": "Get friends list"
        }
    }), 200

# -----------------------------
# Run Server
# -----------------------------
if __name__ == '__main__':
    print("Starting Free Fire Friend Manager...")
    print(f"Server running on: http://localhost:5000")
    print(f"API endpoints:")
    print(f"  POST /api/process-token       - Process tokens")
    print(f"  GET  /api/get-player-info     - Get player info (sync)")
    print(f"  GET  /api/get-player-info-async - Get player info (async)")
    print(f"  GET  /adding_friend           - Add friend")
    print(f"  GET  /remove_friend           - Remove friend")
    print(f"  GET  /get_friends_list        - Get friends list")
    print(f"  GET  /health                  - Health check")
    print("\nMake sure index.html is in the same directory!")
    app.run(host='0.0.0.0', port=5000, debug=True)