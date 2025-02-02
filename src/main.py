#author: NaOH_HaN
#date: 2025-2-2

'''
Notes:
1.EFS Encryption requier Windows Pro or higher version.
2.Custom password encryption using [AES-256-CBC] encryption
3.Keys stored in plaintext are saved in [api_key.txt] in the current directory.
4.Sensitive information stored in encrypted form is stored in [config.json].
'''

import os
import json
import sys
import time
from getpass import getpass
# pip install cryptography requests
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64
import requests
import ctypes
from ctypes import wintypes

CONFIG_FILE = 'config.json'
API_KEY_FILE = 'api_key.txt'
pending_confirmation = None
api_key = None
last_decrypt_time = 0
api_key_decrypted = False

# 初始化配置
config = {
    'api_key': {
        'method': None,
        'encrypted_data': None,
        'salt': None,
        'iv': None,
        'path': None
    },
    'env_vars': {
        'base_url': 'https://api.deepseek.com/v1',
        'model': 'deepseek-chat'
    }
}

def load_config():
    global config
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config.update(json.load(f))

def save_config():
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def pad(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def encrypt_with_password(password, plaintext):
    salt = os.urandom(16)
    iv = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_data = pad(plaintext.encode())
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'salt': base64.b64encode(salt).decode(),
        'iv': base64.b64encode(iv).decode()
    }

def decrypt_with_password(password, ciphertext, salt, iv):
    ciphertext = base64.b64decode(ciphertext)
    salt = base64.b64decode(salt)
    iv = base64.b64decode(iv)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(decrypted_data).decode()

def windows_encrypt_file(filepath):
    try:
        if not os.path.exists(filepath):
            open(filepath, 'w').close()
        filepath = os.path.abspath(filepath)
        success = ctypes.windll.advapi32.EncryptFileW(filepath)
        if not success:
            raise ctypes.WinError()
        return True
    except Exception as e:
        print(f"EFS加密失败: {e}")
        return False

def handle_initial_setup():
    global api_key
    api_key = getpass("请输入DeepSeek API秘钥: ")
    
    print("是否存储API秘钥？(y/n)")
    choice = input().lower()
    if choice != 'y':
        return
    
    print("选择存储方式:")
    print("1. 不加密存储（警告：明文存储）")
    print("2. 自定义密码加密")
    print("3. Windows EFS加密")
    method = input("请输入选项数字: ")
    
    if method == '1':
        with open(API_KEY_FILE, 'w') as f:
            f.write(api_key)
        config['api_key'].update({
            'method': 'plain',
            'path': API_KEY_FILE
        })
    elif method == '2':
        password = getpass("设置加密密码: ")
        encrypted = encrypt_with_password(password, api_key)
        config['api_key'].update({
            'method': 'custom',
            'encrypted_data': encrypted['ciphertext'],
            'salt': encrypted['salt'],
            'iv': encrypted['iv']
        })
    elif method == '3':
        if os.name != 'nt':
            print("EFS仅支持Windows系统")
            return
        with open(API_KEY_FILE, 'w') as f:
            f.write(api_key)
        if windows_encrypt_file(API_KEY_FILE):
            config['api_key'].update({
                'method': 'efs',
                'path': API_KEY_FILE
            })
        else:
            return
    else:
        print("无效选项")
        return
    
    save_config()

def decrypt_api_key():
    global api_key, last_decrypt_time, api_key_decrypted
    # 获取存储方法（带默认值）
    method = config['api_key'].get('method')
    if not method:
        print("错误：未找到API秘钥存储记录")
        return False
    
    if method == 'plain':
        with open(config['api_key']['path'], 'r') as f:
            api_key = f.read().strip()
    elif method == 'custom':
        password = getpass("输入解密密码: ")
        try:
            api_key = decrypt_with_password(
                password,
                config['api_key']['encrypted_data'],
                config['api_key']['salt'],
                config['api_key']['iv']
            )
        except Exception as e:
            print("解密失败:", e)
            return False
    elif method == 'efs':
        try:
            with open(config['api_key']['path'], 'r') as f:
                api_key = f.read().strip()
        except Exception as e:
            print("读取加密文件失败:", e)
            return False
    else:
        print("未知的存储方法")
        return False
    
    last_decrypt_time = time.time()
    api_key_decrypted = True
    return True

def check_decrypt():
    # 先检查是否有存储记录
    if not config['api_key'].get('method'):
        print("没有存储的API秘钥")
        return False
    global last_decrypt_time, api_key_decrypted
    if not api_key_decrypted or (time.time() - last_decrypt_time) > 900:
        print("需要重新验证以访问API秘钥")
        if not decrypt_api_key():
            return False
    return True

def handle_api_show():
    # 前置检查：是否存储过秘钥
    storage_method = config['api_key'].get('method')
    if not storage_method:
        print("没有保存的API秘钥！")
        return
    
    # 继续原有流程
    if check_decrypt():
        print(f"当前API秘钥: {api_key}")

def handle_api_set():
    global api_key
    new_key = getpass("输入新API秘钥: ")
    api_key = new_key
    print("API秘钥已更新")

def handle_api_clear():
    if not config['api_key'].get('method'):
        print("没有可清除的API秘钥")
        return
    global pending_confirmation
    print("确认要清除API秘钥吗？请输入/confirm确认")
    pending_confirmation = 'api_clear'

def handle_confirm():
    global pending_confirmation, api_key
    if pending_confirmation == 'api_clear':
        choice = input("确认清除API秘钥？[y/n]: ").lower()
        if choice == 'y':
            config['api_key'] = {
                'method': None,
                'encrypted_data': None,
                'salt': None,
                'iv': None,
                'path': None
            }
            save_config()
            api_key = None
            print("API秘钥已清除")
        pending_confirmation = None

def handle_model_list():
    print("可用模型:")
    print("- deepseek-chat")
    print("- deepseek-coder")

def handle_model_set(parts):
    if len(parts) < 3:
        print("用法: /model set <模型名称>")
        return
    model = parts[2]
    config['env_vars']['model'] = model
    save_config()
    print(f"模型已设置为 {model}")

def handle_env_list():
    print("环境变量:")
    for k, v in config['env_vars'].items():
        print(f"{k}: {v}")

def handle_env_set(parts):
    if len(parts) < 4:
        print("用法: /env set <键> <值>")
        return
    key = parts[2]
    value = parts[3]
    config['env_vars'][key] = value
    save_config()
    print(f"{key} 已设置为 {value}")

def send_to_deepseek(prompt):
    url = f"{config['env_vars']['base_url']}/chat/completions"
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    data = {
        "model": config['env_vars']['model'],
        "messages": [{"role": "user", "content": prompt}],
        "stream": True
    }
    
    try:
        response = requests.post(url, headers=headers, json=data, stream=True)
        for line in response.iter_lines():
            if line:
                decoded = line.decode('utf-8')
                if decoded.startswith('data: '):
                    json_data = decoded[6:]
                    if json_data.strip() == '[DONE]':
                        break
                    try:
                        chunk = json.loads(json_data)
                        content = chunk['choices'][0]['delta'].get('content', '')
                        print(content, end='', flush=True)
                    except:
                        pass
        print()
    except Exception as e:
        print(f"API请求失败: {e}")

#/about
def handle_about():
    about_info = """
    ChatWith - 命令行AI对话工具
    ===========================
    
    ChatWith Client
    - Version 0.23
    - Copyright © 2025 NaOH_HaN 
    
    本软件依据 Apache License 2.0 协议开源
    Licensed under the Apache License, Version 2.0 (the "License");
    You may not use this file except in compliance with the License.
    You may obtain a copy of the License at [https://www.apache.org/licenses/LICENSE-2.0].
    """
    print(about_info)

def main():
    global api_key, config
    
    load_config()
    
    if config['api_key'].get('method'):
        if config['api_key']['method'] == 'custom':
            if not decrypt_api_key():
                print("无法解密API秘钥")
                return
        else:
            if not decrypt_api_key():
                print("无法读取API秘钥")
                return
    else:
        handle_initial_setup()
        if not api_key:
            print("首次使用需要设置API秘钥")
            return
    
    print("DeepSeek对话系统已就绪（输入/exit退出）")
    while True:
        try:
            user_input = input("> ").strip()
            if not user_input:
                continue
            
            if user_input.startswith('/'):
                parts = user_input.split()
                cmd = parts[0][1:]
                
                if cmd == 'exit':
                    break
                elif cmd == 'confirm':
                    handle_confirm()
                elif cmd == 'about':
                    handle_about()
                elif cmd == 'api':
                    if len(parts) < 2:
                        print("用法: /api [show/set/clear]")
                    else:
                        subcmd = parts[1]
                        if subcmd == 'show':
                            handle_api_show()
                        elif subcmd == 'set':
                            handle_api_set()
                        elif subcmd == 'clear':
                            handle_api_clear()
                        else:
                            print("未知的api命令")
                elif cmd == 'model':
                    if len(parts) < 2:
                        print("用法: /model [list/set]")
                    else:
                        subcmd = parts[1]
                        if subcmd == 'list':
                            handle_model_list()
                        elif subcmd == 'set':
                            handle_model_set(parts)
                        else:
                            print("未知的model命令")
                elif cmd == 'env':
                    if len(parts) < 2:
                        print("用法: /env [list/set]")
                    else:
                        subcmd = parts[1]
                        if subcmd == 'list':
                            handle_env_list()
                        elif subcmd == 'set':
                            handle_env_set(parts)
                        else:
                            print("未知的env命令")
                else:
                    print("未知命令")
            else:
                send_to_deepseek(user_input)
        
        except KeyboardInterrupt:
            print("\n输入/exit退出程序")
        except Exception as e:
            print(f"发生错误: {e}")

if __name__ == "__main__":
    main()