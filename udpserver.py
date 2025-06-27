import socket
import random
import time
import struct
from threading import Thread, Lock
from collections import OrderedDict


class UDPServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)#udp套接字
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((host, port))#绑定端口号和ip地址
        except Exception as e:
            print("绑定失败")
            raise
        self.drop_rate = 0.1
        self.window_size = 4  # 接收窗口大小，限制能接受的个数
        self.client_states = {}
        self.lock = Lock()

    def start(self):
        print(f"服务器正在监听 {self.host}:{self.port}")
        try:
            while True:
                try:
                    data, addr = self.sock.recvfrom(1024)#接收消息，阻塞接收udp数据
                    thread = Thread(target=self.handle_client, args=(data, addr))#创立线程
                    thread.daemon = True#线程守护
                    thread.start()#启动线程
                except ConnectionResetError:
                    print("客户端重连接")
                except Exception as e:
                    print(f"服务器出错: {str(e)}")
        except KeyboardInterrupt:
            print("服务器关闭")
        finally:
            self.sock.close()

    def get_client_state(self, addr):
        with self.lock:#用lock
            if addr not in self.client_states:
                self.client_states[addr] = {
                    'connected': False,#未连接
                    'expected_seq': 0,#期待下一个需要为0
                    'buffer': OrderedDict(),  # 缓存乱序到达的包
                    'window_start': 0,#开始窗口位置
                    'window_end': self.window_size - 1#结束窗口位置
                }
            return self.client_states[addr]

    def check_nor(self,date):
        checksum=0
        for byte in date:
            checksum^=byte
        return checksum & 0xFFFF#确保十六位

    def handle_client(self, data, addr):
        if len(data) < 12:#要求长度不能小于包的长度12
            print(f"来自 {addr} 的无效数据包长度 {len(data)}")
            return

        try:
            header = data[:12]
            #类型，序列号，长度，时间戳，校验和
            type_, seq, length, timestamp, checksum = struct.unpack('!BBIIH', header)#从header中读取数据
            client_state = self.get_client_state(addr)#初始化
            #date=data[12:]
            # 连接建立
            if type_ == 0x01:  # SYN
                print(f"接收到来自 {addr} 的SYN请求")
                if random.random() > self.drop_rate:#模拟丢包
                    temptime = int(time.time() * 1000) % 4294967296
                    syn_ack = struct.pack('!BBIIH', 0x02, 0, 0, temptime, 0)#B是1个字节，I是4个字节，H是两个字节
                    self.sock.sendto(syn_ack, addr)#发送SYN-ACK
                    client_state['connected'] = True#表示建立连接
                    client_state['expected_seq'] = 0
                    client_state['buffer'].clear()
                    client_state['window_start'] = 0
                    client_state['window_end'] = self.window_size - 1
                    print(f"发送SYN-ACK到 {addr}")
                else:
                    print(f"SYN-ACK丢失")

            # 数据传输
            elif type_ == 0x03 and client_state['connected']:  # DATA
                # 检查是否在接收窗口内
                if client_state['window_start'] <= seq <= client_state['window_end']:
                    if random.random() > self.drop_rate and self.check_nor(data[12:])==checksum:#相当于校验
                        # 发送ACK
                        temptime = int(time.time() * 1000) % 4294967296
                        ack = struct.pack('!BBIIH', 0x04, seq, 0, temptime, 0)
                        self.sock.sendto(ack, addr)

                        # 缓存数据包
                        if seq not in client_state['buffer']:
                            client_state['buffer'][seq] = data
                            print(f"已缓存来自 {addr} 的数据包 #{seq}，已发送ACK")

                        # 检查是否可以交付数据
                        while client_state['expected_seq'] in client_state['buffer']:
                            # 这里可以处理数据
                            print(f"已交付来自 {addr} 的数据包 #{client_state['expected_seq']}")
                            del client_state['buffer'][client_state['expected_seq']]
                            client_state['expected_seq'] += 1

                            # 移动窗口
                            client_state['window_start'] = client_state['expected_seq']
                            client_state['window_end'] = client_state['window_start'] + self.window_size - 1
                    else:
                        print(f"模拟丢失来自 {addr} 的数据包 #{seq}")
                else:
                    print(
                        f"来自 {addr} 的数据包 #{seq} 不在窗口 [{client_state['window_start']}, {client_state['window_end']}] 范围内")
                    #ACK
                    # temptime = int(time.time() * 1000) % 4294967296
                    # ack = struct.pack('!BBIIH', 0x04, client_state['expected_seq'] - 1, 0, temptime, 0)
                    # self.sock.sendto(ack, addr)

            # 连接终止
            elif type_ == 0x05:  # FIN
                print(f"接收到来自 {addr} 的FIN请求")
                if random.random() > self.drop_rate:
                    temptime = int(time.time() * 1000) % 4294967296
                    fin_ack = struct.pack('!BBIIH', 0x05, 0, 0, temptime, 0)
                    self.sock.sendto(fin_ack, addr)
                    client_state['connected'] = False
                    #socket.close()
                    print(f"发送FIN-ACK到 {addr}，连接已关闭")
                else:
                    print(f"模拟丢失来自 {addr} 的FIN-ACK")

        except struct.error as e:
            print(f"来自 {addr} 的数据包格式无效: {str(e)}")
        except Exception as e:
            print(f"处理客户端 {addr} 时出错: {str(e)}")


if __name__ == "__main__":
    try:
        server = UDPServer()
        server.start()
    except Exception as e:
        print(f"连接失败: {str(e)}")