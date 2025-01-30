import tkinter as tk
from tkinter import ttk
import pyperclip
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import win32gui
import win32con
import win32api
import win32con
import threading
import time

class AESConverterWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AES加解密转换器")
        self.root.geometry("800x400")
        
        # 剪切板监听开关
        self.clipboard_monitor = tk.BooleanVar()
        self.clipboard_monitor.set(False)
        
        # 快捷模式开关
        self.quick_mode = tk.BooleanVar()
        self.quick_mode.set(False)
        
        # 顶部工具栏
        self.toolbar = ttk.Frame(self.root)
        self.toolbar.pack(fill=tk.X, padx=5, pady=2)
        self.monitor_cb = ttk.Checkbutton(self.toolbar, text="剪切板监听", variable=self.clipboard_monitor, command=self.on_monitor_change)
        self.monitor_cb.pack(side=tk.RIGHT)
        self.quick_mode_cb = ttk.Checkbutton(self.toolbar, text="快捷模式", variable=self.quick_mode, command=self.toggle_quick_mode)
        self.quick_mode_cb.pack(side=tk.RIGHT, padx=5)
        self.quick_mode_cb.pack_forget()  # 初始隐藏

        # 左侧输入框
        self.left_frame = ttk.LabelFrame(self.root, text="输入文本")
        self.left_frame.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.BOTH, expand=True)
        
        self.input_text = tk.Text(self.left_frame, width=30, height=15)
        self.input_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.input_text.bind('<KeyRelease>', self.on_input_change)

        # 中间箭头和清除按钮
        self.middle_frame = ttk.Frame(self.root)
        self.middle_frame.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(self.middle_frame, text="->").pack(pady=10)
        self.clear_btn = ttk.Button(self.middle_frame, text="清除", command=self.clear_text)
        self.clear_btn.pack(pady=10)
        self.clear_btn.pack_forget()  # 初始隐藏

        # 右侧结果框
        self.right_frame = ttk.LabelFrame(self.root, text="输出结果")
        self.right_frame.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.BOTH, expand=True)
        
        self.output_text = tk.Text(self.right_frame, width=30, height=15)
        self.output_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # 按钮区域
        self.button_frame = ttk.Frame(self.right_frame)
        self.button_frame.pack(pady=5)
        
        ttk.Button(self.button_frame, text="复制", command=self.copy_result).pack(side=tk.LEFT, padx=5)
        
        # 快捷窗口
        self.quick_window = None
        
        # 启动剪切板监听线程
        self.running = True
        self.last_clipboard = ""
        self.monitor_thread = threading.Thread(target=self.monitor_clipboard)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def on_monitor_change(self):
        if self.clipboard_monitor.get():
            self.quick_mode_cb.pack(side=tk.RIGHT, padx=5)
        else:
            self.quick_mode_cb.pack_forget()
            if self.quick_mode.get():
                self.quick_mode.set(False)
                self.toggle_quick_mode()

    def toggle_quick_mode(self):
        if self.quick_mode.get():
            self.create_quick_window()
        else:
            if self.quick_window:
                self.quick_window.destroy()
                self.quick_window = None

    def create_quick_window(self):
        self.quick_window = tk.Toplevel()
        self.quick_window.title("AES快捷转换")
        self.quick_window.geometry("400x200")
        self.quick_window.overrideredirect(True)  # 无边框窗口
        self.quick_window.attributes('-alpha', 0.8)  # 设置透明度
        self.quick_window.attributes('-topmost', True)  # 置顶
        self.quick_window.protocol("WM_DELETE_WINDOW", lambda: self.quick_mode.set(False) or self.toggle_quick_mode())
        self.quick_window.configure(bg='black')  # 设置背景为黑色
        
        # 添加拖动功能
        def start_move(event):
            self.quick_window.x = event.x
            self.quick_window.y = event.y
            
        def on_motion(event):
            deltax = event.x - self.quick_window.x
            deltay = event.y - self.quick_window.y
            x = self.quick_window.winfo_x() + deltax
            y = self.quick_window.winfo_y() + deltay
            self.quick_window.geometry(f"+{x}+{y}")
            
        self.quick_window.bind('<Button-1>', start_move)
        self.quick_window.bind('<B1-Motion>', on_motion)
        
        # 结果显示框
        quick_output = tk.Text(self.quick_window, height=8, bg='black', fg='white')
        quick_output.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        
        # 同步显示结果
        def sync_output(*args):
            quick_output.delete("1.0", tk.END)
            quick_output.insert("1.0", self.output_text.get("1.0", tk.END))
        
        self.output_text.bind('<<Modified>>', sync_output)
        sync_output()  # 初始同步

    def generate_key(self):
        return os.urandom(16)

    def is_aes_text(self, text):
        try:
            # 尝试base64解码
            decoded = base64.b64decode(text)
            # AES加密文本长度应该是48(key+iv)+加密数据
            return len(decoded) >= 48
        except:
            return False

    def encrypt(self, text):
        if not text:
            return ""
            
        try:
            key = self.generate_key()
            iv = os.urandom(16)
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # PKCS7 padding
            data = text.encode()
            pad_len = 16 - (len(data) % 16)
            data += bytes([pad_len]) * pad_len
            
            # 加密
            encrypted = encryptor.update(data) + encryptor.finalize()
            
            # 将key和iv嵌入到加密数据中
            result = key + iv + encrypted
            return base64.b64encode(result).decode()
            
        except Exception as e:
            return f"加密错误: {str(e)}"

    def decrypt(self, text):
        try:
            # Base64解码
            decoded = base64.b64decode(text)
            
            # 提取key、iv和加密数据
            key = decoded[:16]
            iv = decoded[16:32]
            encrypted = decoded[32:]
            
            # 解密
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(encrypted) + decryptor.finalize()
            
            # 去除padding
            pad_len = decrypted[-1]
            decrypted = decrypted[:-pad_len]
            
            return decrypted.decode()
            
        except Exception as e:
            return f"解密错误: {str(e)}"

    def on_input_change(self, event=None):
        input_text = self.input_text.get("1.0", tk.END).strip()
        if input_text:
            self.clear_btn.pack(pady=10)
            if self.is_aes_text(input_text):
                # 如果是AES加密文本则解密
                result = self.decrypt(input_text)
            else:
                # 如果是普通文本则加密
                result = self.encrypt(input_text)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
        else:
            self.clear_btn.pack_forget()
            self.output_text.delete("1.0", tk.END)

    def clear_text(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.clear_btn.pack_forget()

    def copy_result(self):
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            self.last_clipboard = result
            pyperclip.copy(result)

    def monitor_clipboard(self):
        while self.running:
            if self.clipboard_monitor.get():
                try:
                    clipboard_text = pyperclip.paste()
                    if clipboard_text != self.last_clipboard:
                        if clipboard_text == self.output_text.get("1.0", tk.END).strip():
                            self.last_clipboard = clipboard_text
                            continue
                        self.last_clipboard = clipboard_text
                        self.root.after(0, self.process_clipboard_text, clipboard_text)
                except:
                    pass
            time.sleep(0.5)

    def process_clipboard_text(self, text):
        if text:
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", text)
            if self.is_aes_text(text):
                result = self.decrypt(text)
            else:
                result = self.encrypt(text)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
            # 自动复制结果
            self.copy_result()
            
    def run(self):
        self.root.mainloop()
        self.running = False  # 停止监听线程

if __name__ == "__main__":
    app = AESConverterWindow()
    app.run()
