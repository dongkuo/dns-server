import threading
import socket
import socketserver
import redis
import json
from functools import reduce

strict_redis = redis.StrictRedis(host='localhost', port=6379, db=0)


class Scanner:
    """scan bytes"""
    __mark_offset_byte, __mark_offset_bit = 0, 0

    def __init__(self, data: bytes, offset_byte=0, offset_bit=0):
        self.data = data
        self.__offset_byte = offset_byte
        self.__offset_bit = offset_bit

    def next_bits(self, n=1):
        if n > (len(self.data) - self.__offset_byte) * 8 - self.__offset_bit:
            raise RuntimeError('剩余数据不足{}位'.format(n))
        if n > 8 - self.__offset_bit:
            raise RuntimeError('不能跨字节读取读取位')
        result = self.data[self.__offset_byte] >> 8 - self.__offset_bit - n & (1 << n) - 1
        self.__offset_bit += n
        if self.__offset_bit == 8:
            self.__offset_bit = 0
            self.__offset_byte += 1
        return result

    def next_bytes(self, n=1, convert=True, move=True):
        if not self.__offset_bit == 0:
            raise RuntimeError('当前字节不完整，请先读取完当前字节的所有位')
        if n > len(self.data) - self.__offset_byte:
            raise RuntimeError('剩余数据不足{}字节'.format(n))
        result = self.data[self.__offset_byte: self.__offset_byte + n]
        if move:
            self.__offset_byte += n
        if convert:
            result = int.from_bytes(result, 'big')
        return result

    def next_bytes_until(self, stop, convert=True):
        if not self.__offset_bit == 0:
            raise RuntimeError('当前字节不完整，请先读取完当前字节的所有位')
        end = self.__offset_byte
        while not stop(self.data[end], end - self.__offset_byte):
            end += 1
        result = self.data[self.__offset_byte: end]
        self.__offset_byte = end
        if convert:
            if result:
                result = reduce(lambda x, y: y if (x == '.') else x + y,
                                map(lambda x: chr(x) if (31 < x < 127) else '.', result))
            else:
                result = ''
        return result

    def position(self):
        return self.__offset_byte, self.__offset_bit


class Message:
    u"""All communications inside of the domain protocol are carried in a single format called a message"""

    def __init__(self, header, question=None, answer=None, authority=None, additional=None):
        self.header = header
        self.question = question
        self.answer = answer
        self.authority = authority
        self.additional = additional

    def to_bytes(self):
        pass

    @classmethod
    def from_bytes(cls, data):
        scanner = Scanner(data)
        # 读取header
        header = dict()
        header['ID'] = scanner.next_bytes(2)
        header['QR'] = scanner.next_bits(1)
        header['OPCODE'] = scanner.next_bits(4)
        header['AA'] = scanner.next_bits(1)
        header['TC'] = scanner.next_bits(1)
        header['RD'] = scanner.next_bits(1)
        header['RA'] = scanner.next_bits(1)
        header['Z'] = scanner.next_bits(3)
        header['RCODE'] = scanner.next_bits(4)
        header['QDCOUNT'] = scanner.next_bytes(2)
        header['ANCOUNT'] = scanner.next_bytes(2)
        header['NSCOUNT'] = scanner.next_bytes(2)
        header['ARCOUNT'] = scanner.next_bytes(2)
        print('header:', header)
        # 读取question
        questions = list()
        for _ in range(header['QDCOUNT']):
            question = dict()
            question['QNAME'] = scanner.next_bytes_until(lambda current, _: current == 0)
            scanner.next_bytes(1)  # 跳过0
            question['QTYPE'] = scanner.next_bytes(2)
            question['QCLASS'] = scanner.next_bytes(2)
            questions.append(question)
        print('questions:', questions)
        message = Message(header)
        # 读取answer、authority、additional
        rrs = list()
        for i in range(header['ANCOUNT'] + header['NSCOUNT'] + header['ARCOUNT']):
            rr = dict()
            rr['NAME'] = cls.handle_compression(scanner)
            rr['TYPE'] = scanner.next_bytes(2)
            rr['CLASS'] = scanner.next_bytes(2)
            rr['TTL'] = scanner.next_bytes(4)
            rr['RDLENGTH'] = scanner.next_bytes(2)
            # 处理data
            if rr['TYPE'] == 1:  # A记录
                r_data = scanner.next_bytes(rr['RDLENGTH'], False)
                rr['RDATA'] = reduce(lambda x, y: y if (len(x) == 0) else x + '.' + y,
                                     map(lambda num: str(num), r_data))
            elif rr['TYPE'] == 2 or rr['TYPE'] == 5:  # NS与CNAME记录
                rr['RDATA'] = cls.handle_compression(scanner, rr['RDLENGTH'])
            rrs.append(rr)
        answer, authority, additional = list(), list(), list()
        for i, rr in enumerate(rrs):
            if i < header['ANCOUNT']:
                answer.append(rr)
            elif i < header['ANCOUNT'] + header['NSCOUNT']:
                authority.append(rr)
            else:
                additional.append(rr)
        print('answer:', answer)
        print('authority:', authority)
        print('additional:', additional)
        message.header = header
        message.answer = answer
        message.authority = authority
        message.additional = additional
        return message

    @classmethod
    def handle_compression(cls, scanner, length=float("inf")):
        """
        The compression scheme allows a domain name in a message to be represented as either:
            - a pointer
            - a sequence of labels ending in a zero octet
            - a sequence of labels ending with a pointer
        """
        byte = scanner.next_bytes()
        if byte >> 6 == 3:  # a pointer
            pointer = (byte & 0x3F << 8) + scanner.next_bytes()
            return cls.handle_compression(Scanner(scanner.data, pointer))
        data = scanner.next_bytes_until(lambda current, offset: current == 0 or current >> 6 == 3 or offset > length)
        if scanner.next_bytes(move=False) == 0:  # a sequence of labels ending in a zero octet
            scanner.next_bytes()
            return data
        # a sequence of labels ending with a pointer
        result = data + '.' + cls.handle_compression(Scanner(scanner.data, *scanner.position()))
        scanner.next_bytes(2)  # 跳过2个字节的指针
        return result

    def save(self):
        pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        request_data = self.request[0]
        # 将请求转发到 114 DNS
        redirect_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        redirect_socket.sendto(request_data, ('114.114.114.114', 53))
        response_data, address = redirect_socket.recvfrom(1024)
        # 缓存响应结果
        message = Message.from_bytes(response_data)
        message.save()
        # 将114响应响应给客户
        client_socket = self.request[1]
        client_socket.sendto(response_data, self.client_address)


class Server(socketserver.ThreadingMixIn, socketserver.UDPServer):
    def __init__(self, host, handler=Handler):
        super().__init__((host, 53), handler)

    def start(self):
        with self:
            server_thread = threading.Thread(target=self.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            print('The DNS server is running at 172.16.42.254...')
            server_thread.join()


if __name__ == "__main__":
    server = Server('172.16.42.254')
    server.start()
