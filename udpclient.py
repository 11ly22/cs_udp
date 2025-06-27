import socket
import time
import random
import struct
from pickle import FALSE

import pandas as pd
from threading import Timer, Lock
from collections import OrderedDict


class UDPClient:
    def __init__(self, server_ip, server_port):
        self.server_addr = (server_ip, server_port)#地址
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)#接收upd的包
        self.sock.settimeout(0.3)  # 300ms的时间限制
        self.connected = False#连接的状态
        self.base_seq = 0#目前的包(也就是指接收到的包最小的序号)
        self.next_seq = 0#下一个包，也就是要发送的下一个包
        self.window_size_bytes = 400  # W设置窗口大小
        self.current_window_bytes = 0  # 当前包已发送# 字节大小
        self.sent_packets = OrderedDict()  # 存储已发送但未确认的数据包信息
        self.rtt_stats = []#存储所有包的RTT，用于后续的计算
        self.total_packets = 0#总共包的数量
        self.retransmissions = 0#重传的次数
        self.lock = Lock()#线程锁，用来保证多线程环境下共享变量
        self.ack_received = set()#ack接收的数量
        self.timers = {}#每个包的定时器
        self.attempts = 0#尝试次数
        self.d_rate = 0.3  # 丢包率
        self.total_bytes_sent = 0#总共发送大小

    def connect(self):
        if self.attempts >= 5:
            print("连接时间过长，请求次数超过五次,连接暂停")
            return False
        temptime = int(time.time() * 1000) % 4294967296
        syn = struct.pack('!BBIIH', 0x01, 0, 0, temptime, 0)
        self.sock.sendto(syn, self.server_addr)
        print("发送SYN,请求连接")
        self.attempts += 1
        try:
            data, _ = self.sock.recvfrom(1024)
            header = data[:12]
            type_, _, _, _, _ = struct.unpack('!BBIIH', header)
            if type_ == 0x02:  # SYN-ACK
                self.connected = True
                print("接收到SYN-ACK,连接建立")
                return True
        except socket.timeout:#超时
            print("连接超时，重新发送")
            return self.connect()

        return False

    def check_nor(self, date):#这个是用来模拟包的检验
        checksum = 0
        for byte in date:
            checksum ^= byte
        return checksum & 0xFFFF

    def get_timeout_interval(self):
        if not self.rtt_stats:  # 如果没有RTT数据，使用默认值
            return 0.3
        avg_rtt = sum(self.rtt_stats) / len(self.rtt_stats)
        return min(avg_rtt/1000, 0.3)  # 确保在0.1s到2.0s之间

    def send_data(self, num_packets=30):
        if not self.connected:
            print("没有连接到服务器")
            return

        while self.next_seq < num_packets:
            while (self.next_seq < num_packets and
                   self.current_window_bytes < self.window_size_bytes):#这个表示当前所占有的包的大小小于400
                data_size = random.randint(28, 68)

                data = f"Packet data {self.next_seq}".ljust(data_size)

                timestamp = int(time.time() * 1000) % 4294967296
                header = struct.pack('!BBIIH', 0x03, self.next_seq, len(data), timestamp, self.check_nor(data.encode()))
                packet = header + data.encode()
                packet_size = len(packet)  # Total packet size

                with self.lock:
                    if random.random() > self.d_rate:#这个用来模拟传输过程中包被破坏
                        self.sock.sendto(packet, self.server_addr)
                    else:
                        self.sock.sendto(struct.pack('!BBIIH', 0x03, self.next_seq, len(data), timestamp,
                                                     self.check_nor(data.encode() + b'\'')), self.server_addr)

                    self.total_packets += 1
                    self.current_window_bytes += packet_size  # Track window usage

                    self.sent_packets[self.next_seq] = {#记录发送的包
                        'packet': packet,
                        'timestamp': timestamp,
                        'retries': 0,
                        'start_byte': self.total_bytes_sent,
                        'size': packet_size
                    }

                    # 启动定时器
                    timeout_interval = self.get_timeout_interval()
                    self.timers[self.next_seq] = Timer(timeout_interval, self.retransmit_packet, args=[self.next_seq])
                    self.timers[self.next_seq].start()

                    end_byte = self.total_bytes_sent + packet_size - 1 - 12
                    print(
                        f"第{self.next_seq}个（第{self.total_bytes_sent}~{end_byte}字节）client端已经发送, 包大小: {packet_size}字节")
                    self.total_bytes_sent += packet_size - 12
                    self.next_seq += 1

            # 检验是否有ack
            self.check_acknowledgements()

    def retransmit_packet(self, seq_num):
        with self.lock:
            if seq_num in self.sent_packets and seq_num not in self.ack_received:#表示已经发送但是未能接收到
                packet_info = self.sent_packets[seq_num]
                packet_info['retries'] += 1
                packet_info['timestamp'] = int(time.time() * 1000) % 4294967296

                if random.random() > self.d_rate:#这个既可以表示丢包又可以表示包的破损
                    self.sock.sendto(packet_info['packet'], self.server_addr)

                self.total_packets += 1
                self.retransmissions += 1

                end_byte = packet_info['start_byte'] + packet_info['size'] - 1 - 12
                print(
                    f"重传第{seq_num}个（第{packet_info['start_byte']}~{end_byte}字节）数据包, 包大小: {packet_info['size']}字节")

                # 重新开始计时
                timeout_interval = self.get_timeout_interval()
                self.timers[seq_num] = Timer(timeout_interval, self.retransmit_packet, args=[seq_num])
                self.timers[seq_num].start()

    def check_acknowledgements(self):
        try:
            data, _ = self.sock.recvfrom(1024)
            header = data[:12]
            type_, ack_seq, _, timestamp, _ = struct.unpack('!BBIIH', header)

            if type_ == 0x04:  # ACK
                with self.lock:
                    if ack_seq not in self.ack_received:
                        self.ack_received.add(ack_seq)

                        # Calculate RTT
                        if ack_seq in self.sent_packets:
                            rtt = int(time.time() * 1000) - self.sent_packets[ack_seq]['timestamp']
                            self.rtt_stats.append(rtt)

                            # Stop timer and free window space
                            if ack_seq in self.timers:
                                self.timers[ack_seq].cancel()#中断计时器
                                del self.timers[ack_seq]

                            packet_info = self.sent_packets[ack_seq]
                            self.current_window_bytes -= packet_info['size']  #窗口变化

                            end_byte = packet_info['start_byte'] + packet_info['size'] - 1 - 12
                            print(f"第{ack_seq}个（第{packet_info['start_byte']}~{end_byte}字节）server端已经收到，RTT是 {rtt} ms, 包大小: {packet_info['size']}字节")


                        while self.base_seq in self.ack_received:
                            if self.base_seq in self.sent_packets:
                                del self.sent_packets[self.base_seq]
                            self.base_seq += 1

        except socket.timeout:
            pass

    def disconnect(self):
        if not self.connected:
            return

        with self.lock:
            for timer in self.timers.values():
                timer.cancel()
            self.timers.clear()

        temptime = int(time.time() * 1000) % 4294967296
        fin = struct.pack('!BBIIH', 0x05, 0, 0, temptime, 0)
        self.sock.sendto(fin, self.server_addr)
        print("Sent FIN")

        try:
            data, _ = self.sock.recvfrom(1024)
            header = data[:12]
            type_, _, _, _, _ = struct.unpack('!BBIIH', header)
            if type_ == 0x05:
                print("Received FIN-ACK, connection closed")
        except socket.timeout:
            print("Timeout waiting for FIN-ACK")

        self.connected = False

    def print_stats(self):
        if self.total_packets == 0:
            print("没有数据包被发送")
            return

        loss_rate = (self.retransmissions / self.total_packets) * 100
        print(f"\n汇总信息:")
        print(f"总发送包数: {self.total_packets}")
        print(f"重传次数: {self.retransmissions}")
        print(f"丢包率: {loss_rate:.2f}%")

        if self.rtt_stats:
            rtt_series = pd.Series(self.rtt_stats)
            print(f"最大RTT: {rtt_series.max()} ms")
            print(f"最小RTT: {rtt_series.min()} ms")
            print(f"平均RTT: {rtt_series.mean()} ms")
            print(f"RTT标准差: {rtt_series.std()} ms")


if __name__ == "__main__":
    try:
        server_ip = input("请输入服务器IP: ")
        server_port = int(input("请输入端口: "))

     #   print(f"准备连接 {server_ip}:{server_port}...")
        client = UDPClient(server_ip, server_port)

        if client.connect():
            try:
                print("开始传输数据...")
                client.send_data(30)
            except KeyboardInterrupt:
                print("\n用户中断传输")
            except Exception as e:
                print(f"传输错误: {str(e)}")
            finally:
                client.disconnect()
                client.print_stats()
    except Exception as e:
        print(f"程序错误: {str(e)}")