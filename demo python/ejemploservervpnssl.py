import socket
import ssl

def start_ssl_server():
    # Configuración del servidor
    host = '0.0.0.0'  # Escuchar en todas las interfaces
    port = 8080
    certfile = 'cert.pem'  # Ruta al archivo del certificado SSL
    keyfile = 'key.pem'    # Ruta al archivo de la clave privada

    # Crear un socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)  # Escuchar una conexión

    print(f"Servidor SSL escuchando en el puerto {port}...")

    # Envolver el socket con SSL
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    with ssl_context.wrap_socket(server_socket, server_side=True) as ssl_socket:
        # Aceptar una conexión
        conn, addr = ssl_socket.accept()
        print(f"Conexión establecida con: {addr}")

        with conn:
            # Recibir un mensaje del cliente
            data = conn.recv(1024).decode('utf-8')
            print(f"Mensaje recibido: {data}")

            # Responder al cliente
            response = "Mensaje recibido correctamente"
            conn.sendall(response.encode('utf-8'))

        print("Cerrando conexión...")

if __name__ == "__main__":
    start_ssl_server()
