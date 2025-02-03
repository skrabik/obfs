import socket
import struct
import logging
import select
import traceback
from threading import Thread
from src import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def safe_recv(sock, buf, done, /):
    try:
        packet = sock.recv(4096)
        if len(packet) > 0:
            buf += packet
        else:
            done = True
    except Exception as e:
        logging.warning(f'{str(e)}\n{traceback.format_exc()}')
        done = True
    return buf, done

def safe_send(sock, buf, done, /):
    try:
        bytes_sent = sock.send(buf)
        buf = buf[bytes_sent : ]
    except Exception as e:
        logging.warning(f'{str(e)}\n{traceback.format_exc()}')
        done = True
    return buf, done

def safe_sendfinal(sock, buf):
    try:
        sock.sendall(buf)
    except:
        pass

class ProxyTCPserver:
    def __init__(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # вот мой сервер
        _config = config.Config()
        self._host = _config.config['host'] 
        self._port = _config.config['port']  
      

    def run(self):
        self._server_socket.bind((self._host, self._port))
        logging.info(f"Прокси-сервер запущен на {self._host}:{self._port}")

        self._server_socket.listen(10)

        while True:
            client_socket, client_address = self._server_socket.accept()
            logging.info(f"Подключение от {client_address}")
            logging.info(client_socket)
            # self.handle_client(client_socket)

            Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        # разбираем запрос от клиента
        header = client_socket.recv(9)
        dest_addr, dest_port = self.parse_header(header)
        logging.info(f"Перенаправление на {dest_addr}:{dest_port}")

        remote_socket = self.connect_to_remote(dest_addr, dest_port)

        # отправляем успешный ответ клиенту
        self.write_reply(client_socket, dest_addr, dest_port)

        self.stream_tcp(client_socket, remote_socket)

    def write_reply(self, sock, addr, port):
        logging.info(f'Reply: {addr};{port}')
        reply = struct.pack('!BBH', 0x00, 0x5A, port)
        reply += socket.inet_pton(socket.AF_INET, addr)
        logging.info('Answer to client ' + str(reply))
        sock.sendall(reply)


    def stream_tcp(self, socket_a, socket_b, /):
        
        sockets_list = [socket_a, socket_b]
        buf_a2b, buf_b2a = b'', b''
        done = False
        
        while not done:
            read_ready, write_ready, _ = select.select(sockets_list, sockets_list, [], 0.5)
            
            if socket_a in read_ready:
                buf_a2b, done = safe_recv(socket_a, buf_a2b, done)
            if socket_b in read_ready:
                buf_b2a, done = safe_recv(socket_b, buf_b2a, done)
            
            if socket_a in write_ready:
                buf_b2a, done = safe_send(socket_a, buf_b2a, done)
            if socket_b in write_ready:
                buf_a2b, done = safe_send(socket_b, buf_a2b, done)
        
        safe_sendfinal(socket_a, buf_b2a)
        safe_sendfinal(socket_b, buf_a2b)
        
    def write_socks4_reply(self, status, addr = '0.0.0.0', port = 0, /):
        logging.debug(f'Reply: {status};{addr};{port}')
        reply = struct.pack('!BBH', 0x00, status, port)
        reply += socket.inet_pton(socket.AF_INET, addr)
        logging.info('Answer to client ' + str(reply))
        self._socket.sendall(reply)

    def parse_header(self, header):
        dest_addr = socket.inet_ntoa(header[4:8]) 
        dest_port = struct.unpack('>H', header[2:4])[0] 
        return dest_addr, dest_port

    def connect_to_remote(self, host, port):
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((host, port))
        return remote_socket