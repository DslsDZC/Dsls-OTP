import os
import sys
import struct
import json
import numpy as np
import secrets
import time
import random
import hashlib
import base64
import zlib
import socket
import threading
import select
import ctypes
import platform
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import constant_time
from getpass import getpass
import argparse

class SecurityError(Exception):
    pass

class SecureMemory:
    @staticmethod
    def secure_erase(data):
        if isinstance(data, (bytes, bytearray)):
            if isinstance(data, bytes):
                data = bytearray(data)
            for i in range(len(data)):
                data[i] = 0
            return bytes(data)
        return None

    @staticmethod
    def secure_zero_memory(data):
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, bytes):
            ba = bytearray(data)
            for i in range(len(ba)):
                ba[i] = 0
            return bytes(ba)
        return None

class DslsQuantumLib:
    @staticmethod
    def generate_kyber_keypair(mode="dsls-kyber768"):
        key_size = {
            "dsls-kyber512": (800, 768),
            "dsls-kyber768": (1184, 1088),
            "dsls-kyber1024": (1568, 1440)
        }.get(mode, (1184, 1088))
        
        public_key = secrets.token_bytes(key_size[0])
        private_key = secrets.token_bytes(key_size[1])
        return public_key, private_key

    @staticmethod
    def kyber_encapsulate(public_key, mode="dsls-kyber768"):
        key_size = {
            "dsls-kyber512": 32,
            "dsls-kyber768": 32,
            "dsls-kyber1024": 32
        }.get(mode, 32)
        
        shared_secret = secrets.token_bytes(key_size)
        # 将公钥对象序列化为字节
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 使用序列化后的字节进行操作
        half_len = len(public_key_bytes) // 2
        ciphertext = public_key_bytes[:half_len] + shared_secret
        return ciphertext, shared_secret

    @staticmethod
    def kyber_decapsulate(private_key, ciphertext, mode="dsls-kyber768"):
        key_size = {
            "dsls-kyber512": 32,
            "dsls-kyber768": 32,
            "dsls-kyber1024": 32
        }.get(mode, 32)
        
        shared_secret = ciphertext[-key_size:]
        return shared_secret

    @staticmethod
    def dilithium_sign(private_key, data, mode="dsls-dilithium3"):
        sig_size = {
            "dsls-dilithium2": 2420,
            "dsls-dilithium3": 3309,
            "dsls-dilithium5": 4627
        }.get(mode, 3309)
        
        return secrets.token_bytes(sig_size)

    @staticmethod
    def dilithium_verify(public_key, data, signature, mode="dsls-dilithium3"):
        return True  # 模拟实现

class SecurityConstants:
    def __init__(self, lightweight=False):
        self.session_key_length = 16 if lightweight else 32
        self.nonce_length = 8 if lightweight else 12
        self.tag_length = 8 if lightweight else 16
        self.segment_id_size = 4 if lightweight else 8
        self.min_segment_size = 512
        self.max_segment_size = 4096 if lightweight else 65536
        self.salt = secrets.token_bytes(8 if lightweight else 16)
        self.info = b'Dsls-OTP-FileCrypto'
        self.kdf_algorithm = hashes.SHA256 if lightweight else hashes.SHA512
        self.aead_algorithm = algorithms.ChaCha20 if lightweight else algorithms.AES
        self.key_expansion_algorithm = algorithms.ChaCha20
        self.curve = ec.SECP256R1 if lightweight else ec.SECP384R1
        self.version = "2.0"
        self.iteration_count = 50000 if lightweight else 100000
        self.obfuscation_seed = secrets.randbits(32)
        self.key_rotation_size = 1 * 1024 * 1024 * 1024
        self.key_rotation_time = 3600
        self.file_magic = b'Dsls'
        self.file_version = 0x01
        self.quantum_mode = "dsls-kyber768"
        
    def to_dict(self):
        return {
            'session_key_length': self.session_key_length,
            'nonce_length': self.nonce_length,
            'tag_length': self.tag_length,
            'segment_id_size': self.segment_id_size,
            'min_segment_size': self.min_segment_size,
            'max_segment_size': self.max_segment_size,
            'salt': self.salt.hex(),
            'info': self.info.hex(),
            'kdf_algorithm': self.kdf_algorithm.name,
            'aead_algorithm': self.aead_algorithm.name,
            'key_expansion_algorithm': self.key_expansion_algorithm.name,
            'curve': self.curve.name,
            'version': self.version,
            'iteration_count': self.iteration_count,
            'obfuscation_seed': self.obfuscation_seed,
            'key_rotation_size': self.key_rotation_size,
            'key_rotation_time': self.key_rotation_time,
            'file_magic': self.file_magic.hex(),
            'file_version': self.file_version,
            'quantum_mode': self.quantum_mode
        }
    
    def to_bytes(self):
        return json.dumps(self.to_dict()).encode('utf-8')
    
    @staticmethod
    def from_bytes(data):
        try:
            params = json.loads(data.decode('utf-8'))
            sc = SecurityConstants()
            sc.session_key_length = params['session_key_length']
            sc.nonce_length = params['nonce_length']
            sc.tag_length = params['tag_length']
            sc.segment_id_size = params['segment_id_size']
            sc.min_segment_size = params['min_segment_size']
            sc.max_segment_size = params['max_segment_size']
            sc.salt = bytes.fromhex(params['salt'])
            sc.info = bytes.fromhex(params['info'])
            sc.kdf_algorithm = getattr(hashes, params['kdf_algorithm'])
            sc.aead_algorithm = getattr(algorithms, params['aead_algorithm'])
            sc.key_expansion_algorithm = getattr(algorithms, params['key_expansion_algorithm'])
            sc.curve = getattr(ec, params['curve'])
            sc.version = params['version']
            sc.iteration_count = params['iteration_count']
            sc.obfuscation_seed = params['obfuscation_seed']
            sc.key_rotation_size = params['key_rotation_size']
            sc.key_rotation_time = params['key_rotation_time']
            sc.quantum_mode = params.get('quantum_mode', 'dsls-kyber768')
            return sc
        except Exception as e:
            raise SecurityError(f"安全参数解析失败: {str(e)}")

class HardwareDetector:
    @staticmethod
    def detect_aes_ni():
        if platform.system() == "Linux":
            try:
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                return 'aes' in cpuinfo and 'sse4_2' in cpuinfo
            except:
                return False
        elif platform.system() == "Windows":
            try:
                from ctypes import windll
                PF_AES_INSTRUCTIONS_AVAILABLE = 17
                return windll.kernel32.IsProcessorFeaturePresent(PF_AES_INSTRUCTIONS_AVAILABLE) != 0
            except Exception:
                return False
        elif platform.system() == "Darwin":
            try:
                sysctl = ctypes.CDLL('/usr/lib/libSystem.dylib').sysctl
                name = (ctypes.c_int * 2)(22, 0)
                result = ctypes.c_uint(0)
                size = ctypes.c_size_t(ctypes.sizeof(result))
                if sysctl(name, 2, ctypes.byref(result), ctypes.byref(size), None, 0) == 0:
                    return (result.value & (1 << 0)) != 0
                return False
            except:
                return False
        return False

    @staticmethod
    def detect_avx2():
        if platform.system() == "Linux":
            try:
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                return 'avx2' in cpuinfo
            except:
                return False
        elif platform.system() == "Windows":
            try:
                from ctypes import windll
                PF_AVX2_INSTRUCTIONS_AVAILABLE = 18
                return windll.kernel32.IsProcessorFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE) != 0
            except Exception:
                return False
        elif platform.system() == "Darwin":
            try:
                sysctl = ctypes.CDLL('/usr/lib/libSystem.dylib').sysctl
                name = (ctypes.c_int * 2)(22, 0)
                result = ctypes.c_uint(0)
                size = ctypes.c_size_t(ctypes.sizeof(result))
                if sysctl(name, 2, ctypes.byref(result), ctypes.byref(size), None, 0) == 0:
                    return (result.value & (1 << 5)) != 0
                return False
            except:
                return False
        return False

class SIMDOperations:
    @staticmethod
    def simd_xor(data, key):
        if len(data) < 1024:
            return bytes(a ^ b for a, b in zip(data, key[:len(data)]))
        
        try:
            data_arr = np.frombuffer(data, dtype=np.uint64)
            key_arr = np.frombuffer(key, dtype=np.uint64)
            result = np.bitwise_xor(data_arr, key_arr[:len(data_arr)])
            return result.tobytes()[:len(data)]
        except Exception:
            return bytes(a ^ b for a, b in zip(data, key[:len(data)]))

class HardwareAccelerator:
    @staticmethod
    def aes_gcm_encrypt(key, data, nonce):
        if HardwareDetector.detect_aes_ni():
            pass
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, encryptor.tag
    
    @staticmethod
    def aes_gcm_decrypt(key, ciphertext, nonce, tag):
        if HardwareDetector.detect_aes_ni():
            pass
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    @staticmethod
    def chacha_encrypt(key, data, nonce):
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data)
    
    @staticmethod
    def chacha_decrypt(key, ciphertext, nonce):
        return HardwareAccelerator.chacha_encrypt(key, ciphertext, nonce)

class Dsls_OTP_FileEncryptor:
    def __init__(self, security_constants, receiver_public_key):
        self.security_constants = security_constants
        self.receiver_public_key = receiver_public_key
        self.segment_counter = 0
        self.backend = default_backend()
        self.bytes_encrypted = 0
        self.key_start_time = time.time()
        self.session_key = secrets.token_bytes(security_constants.session_key_length)
        self.encrypted_session_key, self.encapsulated_key = self._encrypt_session_key()
    
    def _encrypt_session_key(self):
        encrypted_key, encapsulated_key = DslsQuantumLib.kyber_encapsulate(
            self.receiver_public_key,
            self.security_constants.quantum_mode
        )
        return encrypted_key, encapsulated_key
    
    def _need_key_rotation(self):
        return (self.bytes_encrypted > self.security_constants.key_rotation_size or 
                time.time() - self.key_start_time > self.security_constants.key_rotation_time)
    
    def _rotate_session_key(self):
        if self._need_key_rotation():
            new_session_key = secrets.token_bytes(self.security_constants.session_key_length)
            encrypted_key, encapsulated_key = self._encrypt_session_key()
            self.session_key = new_session_key
            self.encrypted_session_key = encrypted_key
            self.encapsulated_key = encapsulated_key
            self.bytes_encrypted = 0
            self.key_start_time = time.time()
            return True
        return False
    
    def _generate_segment_key(self):
        return secrets.token_bytes(self.security_constants.session_key_length)
    
    def _expand_key(self, key, length):
        try:
            nonce = b'\x00' * 16
            algorithm = self.security_constants.key_expansion_algorithm(key, nonce)
            cipher = Cipher(algorithm, mode=None, backend=self.backend)
            encryptor = cipher.encryptor()
            zeros = b'\x00' * length
            return encryptor.update(zeros)
        except Exception as e:
            raise SecurityError(f"密钥扩展失败: {e}")
    
    def _encrypt_segment_key(self, segment_key, segment_id):
        try:
            algorithm = self.security_constants.aead_algorithm(self.session_key)
            nonce = secrets.token_bytes(self.security_constants.nonce_length)
            
            if algorithm.name == "AES":
                ciphertext, tag = HardwareAccelerator.aes_gcm_encrypt(
                    self.session_key, segment_key, nonce
                )
            else:
                ciphertext = HardwareAccelerator.chacha_encrypt(
                    self.session_key, segment_key, nonce
                )
                tag = b''
            
            return nonce, ciphertext, tag
        except Exception as e:
            raise SecurityError(f"段密钥加密失败: {e}")
    
    def encrypt_segment(self, segment):
        if len(segment) == 0:
            return None
        
        key_rotated = self._rotate_session_key()
        
        segment_key = self._generate_segment_key()
        try:
            expanded_key = self._expand_key(segment_key, len(segment))
            ciphertext = SIMDOperations.simd_xor(segment, expanded_key[:len(segment)])
            segment_id = self.segment_counter
            nonce, enc_segment_key, tag = self._encrypt_segment_key(segment_key, segment_id)
            
            packet = struct.pack('>I', segment_id)
            packet += b'\x01' if key_rotated else b'\x00'
            packet += nonce
            packet += enc_segment_key
            if tag: packet += tag
            packet += ciphertext
            
            self.segment_counter += 1
            self.bytes_encrypted += len(segment)
            return packet
        except SecurityError as e:
            raise e
        except Exception as e:
            raise SecurityError(f"数据段加密失败: {e}")
        finally:
            if isinstance(segment_key, (bytes, bytearray)):
                SecureMemory.secure_zero_memory(segment_key)
    
    def encrypt_data(self, data):
        if not data:
            return []
        
        file_hash = hashlib.sha256(data).digest()
        data = file_hash + data
        
        segments = []
        segment_size = self.security_constants.max_segment_size
        for i in range(0, len(data), segment_size):
            segment = data[i:i+segment_size]
            segments.append(segment)
        
        encrypted_packets = []
        for segment in segments:
            try:
                packet = self.encrypt_segment(segment)
                if packet:
                    padding_len = int(len(packet) * (0.15 + random.random() * 0.15))
                    packet = secrets.token_bytes(padding_len) + packet
                    encrypted_packets.append(packet)
            except SecurityError as e:
                print(f"加密错误: {e}")
                return []
        
        return encrypted_packets

class Dsls_OTP_FileDecryptor:
    def __init__(self, security_constants, session_key):
        self.security_constants = security_constants
        self.session_key = session_key
        self.backend = default_backend()
        self.bytes_decrypted = 0
        self.key_start_time = time.time()
    
    def _need_key_rotation(self):
        return (self.bytes_decrypted > self.security_constants.key_rotation_size or 
                time.time() - self.key_start_time > self.security_constants.key_rotation_time)
    
    def _rotate_session_key(self, new_session_key):
        if new_session_key:
            self.session_key = new_session_key
            self.bytes_decrypted = 0
            self.key_start_time = time.time()
    
    def _expand_key(self, key, length):
        try:
            nonce = b'\x00' * 16
            algorithm = self.security_constants.key_expansion_algorithm(key, nonce)
            cipher = Cipher(algorithm, mode=None, backend=self.backend)
            encryptor = cipher.encryptor()
            zeros = b'\x00' * length
            return encryptor.update(zeros)
        except Exception as e:
            raise SecurityError(f"密钥扩展失败: {e}")
    
    def _decrypt_segment_key(self, nonce, enc_segment_key, tag, segment_id):
        try:
            algorithm = self.security_constants.aead_algorithm(self.session_key)
            
            if algorithm.name == "AES":
                return HardwareAccelerator.aes_gcm_decrypt(
                    self.session_key, enc_segment_key, nonce, tag
                )
            else:
                return HardwareAccelerator.chacha_decrypt(
                    self.session_key, enc_segment_key, nonce
                )
        except InvalidTag:
            raise SecurityError(f"段密钥解密失败: 认证标签无效 (段ID: {segment_id})")
        except Exception as e:
            raise SecurityError(f"段密钥解密失败: {e}")
    
    def decrypt_segment(self, packet):
        start_pos = 0
        while start_pos < len(packet) and packet[start_pos] < 128:
            start_pos += 1
        packet = packet[start_pos:]
        
        segment_id_size = self.security_constants.segment_id_size
        nonce_length = self.security_constants.nonce_length
        tag_length = self.security_constants.tag_length if self.security_constants.aead_algorithm.name == "AES" else 0
        session_key_length = self.security_constants.session_key_length
        
        min_packet_size = segment_id_size + 1 + nonce_length + session_key_length + tag_length
        if len(packet) < min_packet_size:
            raise SecurityError(f"无效的数据包长度: {len(packet)} < {min_packet_size}")
        
        segment_id = struct.unpack('>I', packet[:segment_id_size])[0]
        key_rotation_flag = packet[segment_id_size]
        offset = segment_id_size + 1
        
        nonce = packet[offset:offset+nonce_length]
        offset += nonce_length
        
        enc_start = offset
        enc_segment_key = packet[enc_start:enc_start+session_key_length]
        offset += session_key_length
        
        tag = packet[offset:offset+tag_length] if tag_length else b''
        offset += tag_length
        
        ciphertext = packet[offset:]
        
        new_session_key = None
        if key_rotation_flag:
            new_session_key = secrets.token_bytes(self.security_constants.session_key_length)
        
        segment_key = self._decrypt_segment_key(nonce, enc_segment_key, tag, segment_id)
        
        try:
            expanded_key = self._expand_key(segment_key, len(ciphertext))
            plaintext = SIMDOperations.simd_xor(ciphertext, expanded_key[:len(ciphertext)])
            return segment_id, plaintext, new_session_key
        finally:
            if isinstance(segment_key, (bytes, bytearray)):
                SecureMemory.secure_zero_memory(segment_key)
    
    def decrypt_data(self, packets):
        try:
            decrypted_segments = []
            current_session_key = self.session_key
            for i, packet in enumerate(packets):
                try:
                    segment_id, plaintext, new_session_key = self.decrypt_segment(packet)
                    
                    if new_session_key:
                        self._rotate_session_key(new_session_key)
                        current_session_key = new_session_key
                    
                    decrypted_segments.append((segment_id, plaintext))
                    self.bytes_decrypted += len(plaintext)
                except SecurityError as e:
                    print(f"数据包 {i} 解密失败: {e}")
                    return None
            
            decrypted_segments.sort(key=lambda x: x[0])
            full_data = b''.join(segment[1] for segment in decrypted_segments)
            
            if len(full_data) < 32:
                raise SecurityError("解密数据不完整，缺少文件哈希")
            
            file_hash = full_data[:32]
            file_data = full_data[32:]
            
            calculated_hash = hashlib.sha256(file_data).digest()
            if not constant_time.bytes_eq(file_hash, calculated_hash):
                raise SecurityError("文件完整性校验失败: 文件可能已被篡改")
            
            return file_data
        except Exception as e:
            raise SecurityError(f"数据重组失败: {e}")

def generate_ecc_key_pair(curve=ec.SECP384R1):
    private_key = ec.generate_private_key(curve(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def obfuscate_public_key(public_key, seed):
    pubkey_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    compressed = zlib.compress(pubkey_bytes)
    b64_encoded = base64.b64encode(compressed)
    seed_bytes = seed.to_bytes(4, 'big')
    mask = secrets.token_bytes(len(b64_encoded))
    obfuscated = bytearray()
    for i, b in enumerate(b64_encoded):
        mask_byte = mask[i]
        seed_byte = seed_bytes[i % len(seed_bytes)]
        obfuscated_value = (b ^ mask_byte) + seed_byte
        obfuscated.append(obfuscated_value & 0xFF)
    return seed_bytes + bytes(obfuscated), mask

def deobfuscate_public_key(obfuscated_data, mask, seed):
    seed_bytes = seed.to_bytes(4, 'big')
    b64_encoded = bytearray()
    for i, b in enumerate(obfuscated_data[4:]):
        mask_byte = mask[i]
        seed_byte = seed_bytes[i % len(seed_bytes)]
        b64_encoded.append((b - seed_byte) ^ mask_byte)
    compressed = base64.b64decode(bytes(b64_encoded))
    pubkey_bytes = zlib.decompress(compressed)
    return serialization.load_der_public_key(
        pubkey_bytes,
        backend=default_backend()
    )

class ProtocolMonitor:
    def __init__(self):
        self.start_time = time.time()
        self.bytes_processed = 0
        self.segment_count = 0
        self.errors = 0
        self.network_bytes_sent = 0
        self.network_bytes_received = 0
    
    def update(self, bytes_count, segments=0):
        self.bytes_processed += bytes_count
        self.segment_count += segments
    
    def network_update(self, sent=0, received=0):
        self.network_bytes_sent += sent
        self.network_bytes_received += received
    
    def error_occurred(self):
        self.errors += 1
    
    def get_stats(self):
        duration = time.time() - self.start_time
        throughput = self.bytes_processed / duration if duration > 0 else 0
        network_speed = (self.network_bytes_sent + self.network_bytes_received) / duration if duration > 0 else 0
        return {
            "runtime": duration,
            "throughput": throughput,
            "segments": self.segment_count,
            "errors": self.errors,
            "status": "running" if self.errors == 0 else "warning",
            "network_sent": self.network_bytes_sent,
            "network_received": self.network_bytes_received,
            "network_speed": network_speed
        }
    
    def display_dashboard(self, network_mode=False):
        stats = self.get_stats()
        print("\n=== Dsls-OTP 加密协议监控 ===")
        print(f"运行时间: {stats['runtime']:.2f}秒")
        print(f"处理速度: {stats['throughput']/1024/1024:.2f} MB/s")
        print(f"处理分段: {stats['segments']}")
        print(f"错误计数: {stats['errors']}")
        if network_mode:
            print(f"网络发送: {stats['network_sent']/1024/1024:.2f} MB")
            print(f"网络接收: {stats['network_received']/1024/1024:.2f} MB")
            print(f"网络速度: {stats['network_speed']/1024/1024:.2f} MB/s")
        print(f"状态: {stats['status']}")
        print("==================\n")

class NetworkEncryptor:
    def __init__(self, input_file, receiver_public_key_file, target_ip, target_port, lightweight=False):
        self.input_file = input_file
        self.receiver_public_key_file = receiver_public_key_file
        self.target_ip = target_ip
        self.target_port = target_port
        self.lightweight = lightweight
        self.monitor = ProtocolMonitor()
        self.sock = None
        self.encrypted_packets = []
    
    def _connect_to_target(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.target_ip, self.target_port))
            print(f"成功连接到 {self.target_ip}:{self.target_port}")
            return True
        except Exception as e:
            print(f"连接失败: {e}")
            return False
    
    def _send_data(self, data):
        try:
            total_sent = 0
            while total_sent < len(data):
                sent = self.sock.send(data[total_sent:])
                if sent == 0:
                    raise RuntimeError("网络连接中断")
                total_sent += sent
                self.monitor.network_update(sent=sent)
            return True
        except (RuntimeError, Exception) as e:
            print(f"发送数据失败: {e}")
            return False
    
    def encrypt_and_send(self):
        print("=" * 70)
        print(f"Dsls-OTP 网络加密传输 ({'轻量模式' if self.lightweight else '标准模式'})")
        print(f"目标: {self.target_ip}:{self.target_port}")
        print("=" * 70)
        
        if not self._connect_to_target():
            return
        
        try:
            with open(self.receiver_public_key_file, "rb") as f:
                receiver_public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            print(f"接收方公钥加载成功: {receiver_public_key.curve.name}")
        except Exception as e:
            print(f"加载接收方公钥失败: {e}")
            return
        
        security_constants = SecurityConstants(self.lightweight)
        
        encryptor = Dsls_OTP_FileEncryptor(security_constants, receiver_public_key)
        
        try:
            print(f"读取文件: {self.input_file}")
            with open(self.input_file, 'rb') as f:
                input_data = f.read()
            print(f"文件大小: {len(input_data)} 字节")
            self.monitor.update(len(input_data))
        except Exception as e:
            print(f"读取文件失败: {e}")
            return
        
        print("加密文件内容...")
        try:
            self.encrypted_packets = encryptor.encrypt_data(input_data)
            if not self.encrypted_packets:
                print("加密失败，没有生成任何数据包")
                return
            print(f"生成 {len(self.encrypted_packets)} 个加密数据包")
            self.monitor.update(len(self.encrypted_packets), len(self.encrypted_packets))
        except Exception as e:
            print(f"加密失败: {e}")
            return
        
        print("混淆并嵌入公钥...")
        try:
            obfuscated_pubkey, mask = obfuscate_public_key(receiver_public_key, security_constants.obfuscation_seed)
        except Exception as e:
            print(f"公钥混淆失败: {e}")
            return
        
        print("发送文件头...")
        try:
            header = security_constants.file_magic
            header += bytes([security_constants.file_version])
            header += struct.pack('>I', len(security_constants.to_bytes()))
            header += security_constants.to_bytes()
            header += struct.pack('>I', len(obfuscated_pubkey))
            header += obfuscated_pubkey
            header += struct.pack('>I', len(mask))
            header += mask
            header += struct.pack('>I', len(encryptor.session_key))
            header += encryptor.session_key
            
            if not self._send_data(header):
                return
        except Exception as e:
            print(f"发送文件头失败: {e}")
            return
        
        print("发送加密数据...")
        total_packets = len(self.encrypted_packets)
        for i, packet in enumerate(self.encrypted_packets):
            try:
                packet_header = struct.pack('>I', len(packet))
                if not self._send_data(packet_header + packet):
                    return
                
                if (i + 1) % 100 == 0 or i == total_packets - 1:
                    sys.stdout.write(f"\r已发送: {i+1}/{total_packets} 数据包 [{((i+1)/total_packets)*100:.1f}%]")
                    sys.stdout.flush()
            except Exception as e:
                print(f"\n发送数据包失败: {e}")
                return
        
        print("\n文件发送完成!")
        self.monitor.display_dashboard(network_mode=True)
        self.sock.close()

class NetworkDecryptor:
    def __init__(self, output_file, private_key_file, listen_ip, listen_port, password=None):
        self.output_file = output_file
        self.private_key_file = private_key_file
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.password = password
        self.monitor = ProtocolMonitor()
        self.sock = None
        self.running = True
    
    def _create_listener(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.listen_ip, self.listen_port))
            self.sock.listen(1)
            self.sock.settimeout(5)
            print(f"监听中: {self.listen_ip}:{self.listen_port}")
            return True
        except Exception as e:
            print(f"创建监听器失败: {e}")
            return False
    
    def _receive_data(self, conn, length):
        try:
            data = b''
            while len(data) < length:
                chunk = conn.recv(min(length - len(data), 4096))
                if not chunk:
                    raise RuntimeError("网络连接中断")
                data += chunk
                self.monitor.network_update(received=len(chunk))
            return data
        except (RuntimeError, Exception) as e:
            print(f"接收数据失败: {e}")
            return None
    
    def start_listening(self):
        print("=" * 70)
        print(f"Dsls-OTP 网络解密接收")
        print(f"监听: {self.listen_ip}:{self.listen_port}")
        print("=" * 70)
        
        if not self._create_listener():
            return
        
        try:
            while self.running:
                try:
                    conn, addr = self.sock.accept()
                    print(f"接收到来自 {addr[0]}:{addr[1]} 的连接")
                    self.handle_connection(conn)
                    conn.close()
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"连接处理错误: {e}")
        except KeyboardInterrupt:
            print("\n停止监听...")
        finally:
            self.sock.close()
    
    def handle_connection(self, conn):
        try:
            print("接收文件头...")
            file_magic = self._receive_data(conn, 4)
            if file_magic != b'Dsls':
                print("错误: 无效的文件格式")
                return
            
            file_version = self._receive_data(conn, 1)[0]
            if file_version != 0x01:
                print(f"错误: 不支持的文件版本 {file_version}")
                return
            
            sc_len = struct.unpack('>I', self._receive_data(conn, 4))[0]
            sc_data = self._receive_data(conn, sc_len)
            security_constants = SecurityConstants.from_bytes(sc_data)
            print(f"安全参数版本: {security_constants.version}")
            
            obfuscated_len = struct.unpack('>I', self._receive_data(conn, 4))[0]
            obfuscated_pubkey = self._receive_data(conn, obfuscated_len)
            
            mask_len = struct.unpack('>I', self._receive_data(conn, 4))[0]
            mask = self._receive_data(conn, mask_len)
            
            session_key_len = struct.unpack('>I', self._receive_data(conn, 4))[0]
            session_key = self._receive_data(conn, session_key_len)
            
            with open(self.private_key_file, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=self.password.encode() if self.password else None,
                    backend=default_backend()
                )
            print(f"私钥加载成功: {private_key.curve.name}")
            
            public_key = deobfuscate_public_key(obfuscated_pubkey, mask, security_constants.obfuscation_seed)
            print(f"公钥反混淆成功: {public_key.curve.name}")
            
            decryptor = Dsls_OTP_FileDecryptor(security_constants, session_key)
            
            packets = []
            print("接收加密数据...")
            packet_count = 0
            while True:
                packet_len_data = self._receive_data(conn, 4)
                if not packet_len_data:
                    break
                
                packet_len = struct.unpack('>I', packet_len_data)[0]
                packet_data = self._receive_data(conn, packet_len)
                if not packet_data:
                    break
                
                packets.append(packet_data)
                packet_count += 1
                
                if packet_count % 100 == 0:
                    sys.stdout.write(f"\r已接收: {packet_count} 数据包")
                    sys.stdout.flush()
            
            print(f"\n接收完成，共 {packet_count} 个数据包")
            self.monitor.update(packet_count, packet_count)
            
            print("解密文件内容...")
            decrypted_data = decryptor.decrypt_data(packets)
            if decrypted_data is None:
                print("解密失败")
                return
            
            print(f"解密数据大小: {len(decrypted_data)} 字节")
            self.monitor.update(len(decrypted_data))
            
            print(f"写入解密文件: {self.output_file}")
            with open(self.output_file, 'wb') as f:
                f.write(decrypted_data)
            
            print("文件接收完成!")
            self.monitor.display_dashboard(network_mode=True)
        except Exception as e:
            print(f"处理连接失败: {e}")

def client_encrypt(input_file, output_file, receiver_public_key_file, lightweight=False):
    monitor = ProtocolMonitor()
    print("=" * 70)
    print(f"Dsls-OTP 文件加密系统 ({'轻量模式' if lightweight else '标准模式'})")
    print("=" * 70)
    
    try:
        with open(receiver_public_key_file, "rb") as f:
            receiver_public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        print(f"接收方公钥加载成功: {receiver_public_key.curve.name}")
    except Exception as e:
        print(f"加载接收方公钥失败: {e}")
        return
    
    security_constants = SecurityConstants(lightweight)
    
    if not (0 <= security_constants.obfuscation_seed < 2**32):
        print("错误: obfuscation_seed 必须是一个 32 位无符号整数")
        return
    if not isinstance(receiver_public_key, ec.EllipticCurvePublicKey):
        print("错误: receiver_public_key 必须是 EllipticCurvePublicKey 类型")
        return
    
    encryptor = Dsls_OTP_FileEncryptor(security_constants, receiver_public_key)
    
    try:
        print(f"读取文件: {input_file}")
        with open(input_file, 'rb') as f:
            input_data = f.read()
        print(f"文件大小: {len(input_data)} 字节")
        monitor.update(len(input_data))
    except Exception as e:
        print(f"读取文件失败: {e}")
        return
    
    print("加密文件内容...")
    try:
        encrypted_packets = encryptor.encrypt_data(input_data)
        if not encrypted_packets:
            print("加密失败，没有生成任何数据包")
            return
        print(f"生成 {len(encrypted_packets)} 个加密数据包")
        monitor.update(len(encrypted_packets), len(encrypted_packets))
    except Exception as e:
        print(f"加密失败: {e}")
        return
    
    try:
        obfuscated_pubkey, mask = obfuscate_public_key(receiver_public_key, security_constants.obfuscation_seed)
    except Exception as e:
        print(f"公钥混淆失败: {e}")
        print(f"公钥类型: {type(receiver_public_key)}")
        print(f"Seed: {security_constants.obfuscation_seed}")
        return
    
    try:
        print(f"写入加密文件: {output_file}")
        with open(output_file, 'wb') as f:
            f.write(security_constants.file_magic)
            f.write(bytes([security_constants.file_version]))
            f.write(struct.pack('>I', len(security_constants.to_bytes())))
            f.write(security_constants.to_bytes())
            f.write(struct.pack('>I', len(obfuscated_pubkey)))
            f.write(obfuscated_pubkey)
            f.write(struct.pack('>I', len(mask)))
            f.write(mask)
            f.write(struct.pack('>I', len(encryptor.session_key)))
            f.write(encryptor.session_key)
            
            for packet in encrypted_packets:
                f.write(struct.pack('>I', len(packet)))
                f.write(packet)
        
        print("加密完成!")
        monitor.display_dashboard()
    except Exception as e:
        print(f"写入文件失败: {e}")
        return
    finally:
        if hasattr(encryptor, 'session_key'):
            SecureMemory.secure_zero_memory(encryptor.session_key)

def server_decrypt(input_file, output_file, private_key_file, password=None):
    monitor = ProtocolMonitor()
    print("=" * 70)
    print("Dsls-OTP 文件解密系统")
    print("=" * 70)
    
    try:
        with open(input_file, 'rb') as f:
            file_data = f.read()
        print(f"文件大小: {len(file_data)} 字节")
        monitor.update(len(file_data))
    except Exception as e:
        print(f"读取文件失败: {e}")
        return
    
    offset = 0
    
    file_magic = file_data[offset:offset+4]
    offset += 4
    if file_magic != b'Dsls':
        print("错误: 无效的文件格式")
        return
    
    file_version = file_data[offset]
    offset += 1
    if file_version != 0x01:
        print(f"错误: 不支持的文件版本 {file_version}")
        return
    
    sc_len = struct.unpack('>I', file_data[offset:offset+4])[0]
    offset += 4
    sc_data = file_data[offset:offset+sc_len]
    offset += sc_len
    
    try:
        security_constants = SecurityConstants.from_bytes(sc_data)
        print(f"安全参数版本: {security_constants.version}")
    except Exception as e:
        print(f"解析安全参数失败: {e}")
        return
    
    obfuscated_len = struct.unpack('>I', file_data[offset:offset+4])[0]
    offset += 4
    obfuscated_pubkey = file_data[offset:offset+obfuscated_len]
    offset += obfuscated_len
    
    mask_len = struct.unpack('>I', file_data[offset:offset+4])[0]
    offset += 4
    mask = file_data[offset:offset+mask_len]
    offset += mask_len
    
    session_key_len = struct.unpack('>I', file_data[offset:offset+4])[0]
    offset += 4
    session_key = file_data[offset:offset+session_key_len]
    offset += session_key_len
    
    try:
        with open(private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode() if password else None,
                backend=default_backend()
            )
        print(f"私钥加载成功: {private_key.curve.name}")
    except Exception as e:
        print(f"加载私钥失败: {e}")
        return
    
    try:
        public_key = deobfuscate_public_key(obfuscated_pubkey, mask, security_constants.obfuscation_seed)
        print(f"公钥反混淆成功: {public_key.curve.name}")
    except Exception as e:
        print(f"公钥反混淆失败: {e}")
        return
    
    decryptor = Dsls_OTP_FileDecryptor(security_constants, session_key)
    
    packets = []
    while offset < len(file_data):
        packet_len = struct.unpack('>I', file_data[offset:offset+4])[0]
        offset += 4
        
        if offset + packet_len > len(file_data):
            print(f"数据包不完整，需要 {packet_len} 字节，剩余 {len(file_data) - offset} 字节")
            break
        
        packet = file_data[offset:offset+packet_len]
        offset += packet_len
        packets.append(packet)
    
    print(f"读取 {len(packets)} 个加密数据包")
    monitor.update(len(packets), len(packets))
    
    print("解密文件内容...")
    try:
        decrypted_data = decryptor.decrypt_data(packets)
        if decrypted_data is None:
            print("解密失败")
            return
        print(f"解密数据大小: {len(decrypted_data)} 字节")
        monitor.update(len(decrypted_data))
    except SecurityError as e:
        print(f"安全错误: {e}")
        return
    
    try:
        print(f"写入解密文件: {output_file}")
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        print("解密完成!")
        monitor.display_dashboard()
    except Exception as e:
        print(f"写入文件失败: {e}")
        return
    finally:
        if hasattr(decryptor, 'session_key'):
            SecureMemory.secure_zero_memory(decryptor.session_key)

def generate_key_pair(private_key_file, public_key_file, password=None):
    print("=" * 70)
    print("Dsls-OTP 密钥生成工具")
    print("=" * 70)
    
    if os.path.exists(private_key_file) or os.path.exists(public_key_file):
        print("错误: 密钥文件已存在")
        return
    
    password_protected = False
    if password is None:
        if input("是否使用密码保护私钥? (y/n): ").lower() == 'y':
            password = getpass("输入私钥密码: ")
            password_protected = True
    
    curve = ec.SECP384R1()
    print(f"生成 {curve.name} 密钥对...")
    
    try:
        private_key = ec.generate_private_key(curve, default_backend())
        public_key = private_key.public_key()
        
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        with open(private_key_file, 'wb') as f:
            f.write(private_pem)
        print(f"私钥已保存到: {private_key_file}")
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_file, 'wb') as f:
            f.write(public_pem)
        print(f"公钥已保存到: {public_key_file}")
        
        if password_protected:
            print("警告: 请牢记密码，没有密码将无法使用私钥")
        
        print("密钥生成完成!")
    except Exception as e:
        print(f"密钥生成失败: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Dsls-OTP 文件加密/解密与网络传输系统",
        usage="python dsls-otp.py {encrypt,decrypt,keygen,send,receive} ..."
    )
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    encrypt_parser = subparsers.add_parser("encrypt", help="加密文件")
    encrypt_parser.add_argument("input", help="输入文件路径")
    encrypt_parser.add_argument("output", help="输出文件路径")
    encrypt_parser.add_argument("--receiver-key", required=True, help="接收方公钥文件路径")
    encrypt_parser.add_argument("--lightweight", action="store_true", help="使用轻量级模式")
    
    decrypt_parser = subparsers.add_parser("decrypt", help="解密文件")
    decrypt_parser.add_argument("input", help="输入文件路径")
    decrypt_parser.add_argument("output", help="输出文件路径")
    decrypt_parser.add_argument("--private-key", required=True, help="私钥文件路径")
    decrypt_parser.add_argument("--password", help="私钥密码（如有）")
    
    keygen_parser = subparsers.add_parser("keygen", help="生成密钥对")
    keygen_parser.add_argument("--private-key", default="private_key.pem", help="私钥保存路径")
    keygen_parser.add_argument("--public-key", default="public_key.pem", help="公钥保存路径")
    keygen_parser.add_argument("--password", help="私钥密码（如有）")
    
    send_parser = subparsers.add_parser("send", help="通过网络发送加密文件")
    send_parser.add_argument("input", help="输入文件路径")
    send_parser.add_argument("--receiver-key", required=True, help="接收方公钥文件路径")
    send_parser.add_argument("--target", required=True, help="目标IP地址:端口 (格式: 192.168.1.100:5000)")
    send_parser.add_argument("--lightweight", action="store_true", help="使用轻量级模式")
    
    receive_parser = subparsers.add_parser("receive", help="接收并解密网络文件")
    receive_parser.add_argument("output", help="输出文件路径")
    receive_parser.add_argument("--private-key", required=True, help="私钥文件路径")
    receive_parser.add_argument("--listen", default="0.0.0.0:5000", help="监听地址:端口 (格式: 0.0.0.0:5000)")
    receive_parser.add_argument("--password", help="私钥密码（如有）")
    
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "encrypt":
        client_encrypt(args.input, args.output, args.receiver_key, args.lightweight)
    elif args.command == "decrypt":
        server_decrypt(args.input, args.output, args.private_key, args.password)
    elif args.command == "keygen":
        generate_key_pair(args.private_key, args.public_key, args.password)
    elif args.command == "send":
        target_parts = args.target.split(':')
        if len(target_parts) != 2:
            print("错误: 目标地址格式应为 IP:端口")
            sys.exit(1)
        target_ip, target_port = target_parts
        try:
            target_port = int(target_port)
        except ValueError:
            print("错误: 端口号必须是整数")
            sys.exit(1)
        
        encryptor = NetworkEncryptor(
            args.input, 
            args.receiver_key, 
            target_ip, 
            target_port, 
            args.lightweight
        )
        encryptor.encrypt_and_send()
    elif args.command == "receive":
        listen_parts = args.listen.split(':')
        if len(listen_parts) != 2:
            print("错误: 监听地址格式应为 IP:端口")
            sys.exit(1)
        listen_ip, listen_port = listen_parts
        try:
            listen_port = int(listen_port)
        except ValueError:
            print("错误: 端口号必须是整数")
            sys.exit(1)
        
        decryptor = NetworkDecryptor(
            args.output, 
            args.private_key, 
            listen_ip, 
            listen_port, 
            args.password
        )
        decryptor.start_listening()
