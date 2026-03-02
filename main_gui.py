import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
from crypto_core import IoTPrivacySystem
from chat_crypto import SecureChatSystem
import json

class CryptoApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="cyborg")
        self.title("现代密码学大作业演示系统")
        self.geometry("1050x850") 
        
        self.iot_sys = IoTPrivacySystem()
        self.chat_sys = SecureChatSystem()
        
        self.enc_a = None
        self.enc_b = None
        self.enc_result = None
        
        self.setup_ui()

    def setup_ui(self):
        title_label = ttk.Label(self, text="密码学大作业演示", font=("Helvetica", 22, "bold"), bootstyle="info")
        title_label.pack(pady=10)

        self.notebook = ttk.Notebook(self, bootstyle="info")
        self.notebook.pack(fill=BOTH, expand=True, padx=20, pady=10)

        self.tab_iot = ttk.Frame(self.notebook, padding=15)
        self.tab_chat = ttk.Frame(self.notebook, padding=15)
        
        self.notebook.add(self.tab_iot, text=' 模块一：IoT特征同态加密计算 ')
        self.notebook.add(self.tab_chat, text=' 模块二：混合加密过程可视化 ')

        self.build_iot_tab()
        self.build_chat_tab()

    # ================== 模块一：IoT特征同态加密计算 ==================
    def build_iot_tab(self):
        step1_lf = ttk.Labelframe(self.tab_iot, text=" 步骤 1: 传感器端 (特征加密) ", bootstyle="primary")
        step1_lf.pack(fill=X, pady=5)
        frame_a = ttk.Frame(step1_lf)
        frame_a.pack(fill=X, pady=5, padx=10)
        ttk.Label(frame_a, text="传感器 A 流量特征值:").pack(side=LEFT)
        self.input_a = ttk.Entry(frame_a, width=15)
        self.input_a.pack(side=LEFT, padx=10)
        self.input_a.insert(0, "150.5")
        self.cipher_label_a = ttk.Label(frame_a, text="密文: (等待加密)", bootstyle="secondary", font=("Courier", 9))
        self.cipher_label_a.pack(side=LEFT, padx=10)

        frame_b = ttk.Frame(step1_lf)
        frame_b.pack(fill=X, pady=5, padx=10)
        ttk.Label(frame_b, text="传感器 B 流量特征值:").pack(side=LEFT)
        self.input_b = ttk.Entry(frame_b, width=15)
        self.input_b.pack(side=LEFT, padx=10)
        self.input_b.insert(0, "45.2")
        self.cipher_label_b = ttk.Label(frame_b, text="密文: (等待加密)", bootstyle="secondary", font=("Courier", 9))
        self.cipher_label_b.pack(side=LEFT, padx=10)

        ttk.Button(step1_lf, text="生成密文", bootstyle="primary", command=self.encrypt_data).pack(pady=10)

        step2_lf = ttk.Labelframe(self.tab_iot, text=" 步骤 2: 边缘网关 (密文状态直接计算) ", bootstyle="warning")
        step2_lf.pack(fill=BOTH, expand=True, pady=10)
        control_frame = ttk.Frame(step2_lf)
        control_frame.pack(pady=10)
        ttk.Button(control_frame, text="密文相加 E(A)+E(B)", bootstyle="warning-outline", command=lambda: self.compute("add")).pack(side=LEFT, padx=5)
        ttk.Button(control_frame, text="密文相减 E(A)-E(B)", bootstyle="warning-outline", command=lambda: self.compute("sub")).pack(side=LEFT, padx=5)
        ttk.Label(control_frame, text=" | 标量乘法 k=").pack(side=LEFT)
        self.scalar_k = ttk.Entry(control_frame, width=5)
        self.scalar_k.pack(side=LEFT)
        self.scalar_k.insert(0, "3")
        ttk.Button(control_frame, text="执行 E(A)*k", bootstyle="warning-outline", command=lambda: self.compute("mul")).pack(side=LEFT, padx=5)

        self.math_label = ttk.Label(step2_lf, text="当前计算: 无", font=("Helvetica", 11, "bold"), bootstyle="warning")
        self.math_label.pack(anchor=W, padx=20, pady=5)
        self.result_cipher_text = ttk.Text(step2_lf, height=4, font=("Courier", 9))
        self.result_cipher_text.pack(fill=X, padx=20, pady=5)

        step3_lf = ttk.Labelframe(self.tab_iot, text=" 步骤 3: 云平台中心 (私钥解密) ", bootstyle="success")
        step3_lf.pack(fill=X, pady=5)
        ttk.Button(step3_lf, text=" 验证运算结果", bootstyle="success", command=self.decrypt_result).pack(side=LEFT, padx=20, pady=15)
        self.final_result_var = ttk.StringVar(value="最终解密结果: ?")
        ttk.Label(step3_lf, textvariable=self.final_result_var, font=("Helvetica", 16, "bold"), bootstyle="success").pack(side=LEFT, padx=20)

    def encrypt_data(self):
        try:
            val_a, val_b = float(self.input_a.get()), float(self.input_b.get())
            self.enc_a = self.iot_sys.encrypt_feature(val_a)
            self.enc_b = self.iot_sys.encrypt_feature(val_b)
            c_a_str, c_b_str = str(self.enc_a.ciphertext()), str(self.enc_b.ciphertext())
            self.cipher_label_a.config(text=f"密文: {c_a_str[:25]}...{c_a_str[-10:]}")
            self.cipher_label_b.config(text=f"密文: {c_b_str[:25]}...{c_b_str[-10:]}")
            self.enc_result = None
            self.result_cipher_text.delete(1.0, END)
            self.final_result_var.set("最终解密结果: ?")
        except ValueError:
            messagebox.showerror("错误", "请输入有效数字！")

    def compute(self, op_type):
        if not self.enc_a or not self.enc_b: return
        self.result_cipher_text.delete(1.0, END)
        if op_type == "add":
            self.enc_result = self.iot_sys.homomorphic_add(self.enc_a, self.enc_b)
            self.math_label.config(text="当前计算: 同态加法  -> E(A) + E(B)")
        elif op_type == "sub":
            self.enc_result = self.iot_sys.homomorphic_sub(self.enc_a, self.enc_b)
            self.math_label.config(text="当前计算: 同态减法  -> E(A) - E(B)")
        elif op_type == "mul":
            k = float(self.scalar_k.get())
            self.enc_result = self.iot_sys.homomorphic_mul(self.enc_a, k)
            self.math_label.config(text=f"当前计算: 标量乘法  -> E(A) * {k}")
        res_str = str(self.enc_result.ciphertext())
        self.result_cipher_text.insert(END, f"【生成新密文】:\n{res_str[:150]}......(截断展示)")

    def decrypt_result(self):
        if not self.enc_result: return
        dec_val = self.iot_sys.decrypt_result(self.enc_result)
        self.final_result_var.set(f"最终解密结果: {round(dec_val, 4)}")

    # ================== 模块二：混合加密 ==================
    def build_chat_tab(self):
        # 发送方区域
        sender_lf = ttk.Labelframe(self.tab_chat, text="  发送方 (Alice 的本地处理过程) ", bootstyle="info")
        sender_lf.pack(fill=X, pady=5)
        
        input_frame = ttk.Frame(sender_lf)
        input_frame.pack(fill=X, pady=5)
        ttk.Label(input_frame, text="待发机密信息: ").pack(side=LEFT, padx=10)
        self.msg_input = ttk.Entry(input_frame, width=50, font=("", 11))
        self.msg_input.pack(side=LEFT, padx=5)
        self.msg_input.insert(0, "这是一条给Bob秘密")
        ttk.Button(input_frame, text="执行加密并发送", bootstyle="info", command=self.send_chat).pack(side=LEFT, padx=10)

        # 发送方中间过程展示
        self.sender_log = ttk.Text(sender_lf, height=5, font=("Courier", 9), bg="#1e1e1e", fg="#4CAF50")
        self.sender_log.pack(fill=X, padx=10, pady=5)
        self.sender_log.insert(END, "等待执行加密操作...\n")

        # 网络信道区域
        network_lf = ttk.Labelframe(self.tab_chat, text="  公共网络信道 (抓包视图) ", bootstyle="danger")
        network_lf.pack(fill=BOTH, expand=True, pady=5)
        self.packet_text = ttk.Text(network_lf, height=6, font=("Courier", 9), bg="#2d0000", fg="#ff5252")
        self.packet_text.pack(fill=BOTH, expand=True, padx=10, pady=5)
        self.packet_text.insert(END, "[信道空闲]\n")

        # 接收方区域
        receiver_lf = ttk.Labelframe(self.tab_chat, text="  接收方 (Bob 的本地解密过程) ", bootstyle="success")
        receiver_lf.pack(fill=X, pady=5)
        
        btn_frame = ttk.Frame(receiver_lf)
        btn_frame.pack(fill=X, pady=5)
        ttk.Button(btn_frame, text="从信道接收并解密", bootstyle="success", command=self.receive_chat).pack(side=LEFT, padx=10)
        self.decrypted_msg_var = ttk.StringVar(value="最终明文: (等待接收)")
        ttk.Label(btn_frame, textvariable=self.decrypted_msg_var, font=("微软雅黑", 12, "bold"), bootstyle="success").pack(side=LEFT, padx=10)

        # 接收方中间过程展示
        self.receiver_log = ttk.Text(receiver_lf, height=4, font=("Courier", 9), bg="#1e1e1e", fg="#00BCD4")
        self.receiver_log.pack(fill=X, padx=10, pady=5)
        self.receiver_log.insert(END, " 等待接收数据包...\n")

    def send_chat(self):
        msg = self.msg_input.get()
        if not msg: return
        
        # 调用详细加密方法，获取所有中间变量
        sess_key, cipher_msg, enc_sess_key, packet = self.chat_sys.sender_encrypt_detailed(msg)
        self.current_packet = packet
        
        # 1. 打印发送方处理日志
        self.sender_log.delete(1.0, END)
        log_text = f" 步骤 1: 生成一次性随机 AES 密钥 (Base64): \n  {sess_key}\n"
        log_text += f" 步骤 2: 使用 AES 密钥加密原始消息 (得到密文): \n  {cipher_msg}\n"
        log_text += f" 步骤 3: 使用 Bob 的 RSA 公钥加密 AES 密钥: \n  {enc_sess_key[:80]}..."
        self.sender_log.insert(END, log_text)

        # 2. 打印网络抓包
        self.packet_text.delete(1.0, END)
        self.packet_text.insert(END, f"【网络抓包 JSON】:\n{json.dumps(packet, indent=2)}")
        
        # 3. 重置接收方
        self.decrypted_msg_var.set("最终明文: (等待接收)")
        self.receiver_log.delete(1.0, END)
        self.receiver_log.insert(END, "检测到信道中有新数据包，请点击接收...\n")

    def receive_chat(self):
        if not hasattr(self, 'current_packet'): return
        try:
            # 调用详细解密方法，获取中间变量
            rec_sess_key, dec_msg = self.chat_sys.receiver_decrypt_detailed(self.current_packet)
            
            # 1. 打印接收方处理日志
            self.receiver_log.delete(1.0, END)
            log_text = f" 步骤 1: 使用自身 RSA 私钥解密，恢复出 AES 会话密钥 (Base64): \n  {rec_sess_key}\n"
            log_text += f" 步骤 2: 使用恢复的 AES 密钥解密消息密文，完成还原！\n"
            self.receiver_log.insert(END, log_text)
            
            # 2. 显示最终明文
            self.decrypted_msg_var.set(f"最终明文: {dec_msg}")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()