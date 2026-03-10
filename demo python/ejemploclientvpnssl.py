import socket
import ssl

def connect_to_ssl_server():
    # Configuración del cliente
    server_host = 'localhost'  # Cambiar si el servidor está en otro host
    server_port = 8080
    message = "Hola desde el cliente!"

    # Crear un socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Envolver el socket con SSL
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False  # No verifica el nombre del host
    ssl_context.verify_mode = ssl.CERT_NONE  # No verifica el certificado del servidor (solo para pruebas)

    with ssl_context.wrap_socket(client_socket, server_hostname=server_host) as ssl_socket:
        # Conectarse al servidor
        ssl_socket.connect((server_host, server_port))
        print(f"Conectado al servidor SSL en {server_host}:{server_port}")

        # Enviar un mensaje al servidor
        ssl_socket.sendall(message.encode('utf-8'))
        print(f"Mensaje enviado: {message}")

        # Recibir respuesta del servidor
        response = ssl_socket.recv(1024).decode('utf-8')
        print(f"Respuesta del servidor: {response}")

if __name__ == "__main__":
    connect_to_ssl_server()
