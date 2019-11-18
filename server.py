import socket
import select # para varias conexiones
import hmac
import hashlib
import sqlite3
import ssl


HORASDELOSMENSAJES = []
MY_CLAVE = input("Introduzca la clave para la comprobación de integridad: ")
HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 1234


server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)

server_socket.bind((IP,PORT))
server_socket = ssl.wrap_socket(server_socket,
                                server_side=True,
                                certfile="./certificados/server.crt",
                                keyfile="./certificados/server.key",
                                ssl_version=ssl.PROTOCOL_TLSv1)
server_socket.listen()

sockets_list = [server_socket]
clients = {}


def checkReplayAttack(message):
    horallegada = message.decode('utf-8').split('@')[1]
    if  horallegada in HORASDELOSMENSAJES:
        return False
    else:
        HORASDELOSMENSAJES.append(horallegada)
        return True

def checkIntegridadMensaje(message,mac):
    print(message)
    print(mac)
    calculada = hmac.digest(MY_CLAVE, message, hashlib.sha3_512).hex()
    print(calculada)
    print(mac)
    if calculada == mac.decode('utf-8'):
        return True
    else:
        return False

def receive_message(client_socket):
    try:
        message_header = client_socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False

        message_length = int(message_header.decode("utf-8").strip())
        message = client_socket.recv(message_length)

        return {"header":message_header, "data":message}
    except:
        return False






# Servidor overkill basado en el tutorial de sockets de Harrison Kinsley
while True:
    #print(select.select(sockets_list, [],sockets_list))
    read_sockets, _, exception_sockets = select.select(sockets_list, [],sockets_list)
    # readlist , writelist, error list

    for notified_socket in read_sockets:
        if notified_socket == server_socket:
            #Se ha conectado al servidor




            client_socket, client_adress = server_socket.accept()
            user = receive_message(client_socket)

            if user is False:
                continue

            sockets_list.append(client_socket)
            clients[client_socket] = user
            print(f"Conexion aceptada desde {client_adress[0]}:{client_adress[1]} username:{user['data'].decode('utf-8')}")

        else:
            message = receive_message(notified_socket)
            if message is False:
                print(f"Conexion cerrada desde {clients[notified_socket]['data'].decode('utf-8')}")
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                continue

            user = clients[notified_socket]
            print(f"Mensaje API recibido desde {user['data'].decode('utf-8')}: {message['data'].decode('utf-8')}")


            message2 = receive_message(notified_socket)
            if message2 is False:
                print(f"Conexion cerrada desde {clients[notified_socket]['data'].decode('utf-8')}")
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                continue

            user = clients[notified_socket]
            print(f"Mensaje MAC recibido desde {user['data'].decode('utf-8')}: {message2['data'].decode('utf-8')}")


            # if checkIntegridadMensaje(message['data'],message2['data']):
            #     if checkReplayAttack(message['data']):
            #         print("OK, integridad confirmada")
            #     else:
            #         print("Ataque de replay detectado!!")
            # else:
            #     print("NOPE, integridad comprometida")




            #Enviar mensaje a todos pero al que lo ha mandado
            for client_socket in clients:
                if client_socket != notified_socket:
                    client_socket.send(user['header']+user['data']+message['header']+message['data'])


        for notified_socket in exception_sockets:
            sockets_list.remove(notified_socket)
            del clients[notified_socket]
