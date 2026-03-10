import tkinter as tk
from tkinter import messagebox
import socket
import ssl

# ----------------------------
# CONFIGURACIÓN DE CONEXIÓN
# ----------------------------
HOST = "127.0.0.1"
PORT = 3443

# RF13 - Comunicación via sockets seguros (TLS 1.3)
# RF12 - Interfaz gráfica de usuario
def conectar_servidor():
    try:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE  # Sin verificación (demo — hace posible el MitM)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl_context.wrap_socket(sock, server_hostname=HOST)
        ssl_sock.connect((HOST, PORT))
        return ssl_sock
    except Exception:
        return None

def verificar_conexion():
    global cliente
    if cliente is None:
        messagebox.showerror("Error", "El servidor no está disponible. Inténtelo más tarde.")
        return False
    return True

cliente        = conectar_servidor()
usuario_actual = None
token_actual   = None

# ----------------------------
# RF12 - Interfaz gráfica de usuario
# ----------------------------
root = tk.Tk()
root.title("VPN SSL - Universidad de Sevilla")
root.geometry("300x250")

def mostrar_formulario(titulo):
    formulario = tk.Toplevel(root)
    formulario.title(titulo)
    formulario.geometry("300x200")
    formulario.grab_set()
    formulario.focus_set()
    tk.Label(formulario, text="Nombre de usuario:").pack(pady=5)
    username_entry = tk.Entry(formulario)
    username_entry.pack(pady=5)
    tk.Label(formulario, text="Contraseña:").pack(pady=5)
    password_entry = tk.Entry(formulario, show='*')
    password_entry.pack(pady=5)
    return formulario, username_entry, password_entry

# ----------------------------
# RF1 - Registro de usuarios
# RF2 - Sin duplicados en registro
# ----------------------------
def on_register_click():
    if not verificar_conexion():
        return
    formulario, username_entry, password_entry = mostrar_formulario("Registrarse")

    def registrar():
        usuario   = username_entry.get()
        contrasena = password_entry.get()
        if not usuario or not contrasena:
            messagebox.showerror("Error", "Debe completar todos los campos.")
            return
        try:
            cliente.send(f"REGISTRO:{usuario}:{contrasena}".encode())
            respuesta = cliente.recv(4096).decode()
        except Exception:
            messagebox.showerror("Error", "El servidor no está disponible.")
            return
        if respuesta == "Usuario registrado exitosamente":
            messagebox.showinfo("Éxito", "Registro exitoso. Ahora puede iniciar sesión.")
            formulario.destroy()
        else:
            messagebox.showerror("Error", respuesta)  # RF2 - Informa si el usuario ya existe
            password_entry.delete(0, tk.END)

    tk.Button(formulario, text="Registrarse", command=registrar).pack(pady=20)

# ----------------------------
# RF4 - Inicio de sesión
# RF5 - Verificar credenciales / denegar si no coinciden
# ----------------------------
def on_login_click():
    global usuario_actual, token_actual
    if not verificar_conexion():
        return
    formulario, username_entry, password_entry = mostrar_formulario("Iniciar sesión")

    def login():
        global usuario_actual, token_actual
        usuario    = username_entry.get()
        contrasena = password_entry.get()
        if not usuario or not contrasena:
            messagebox.showerror("Error", "Debe completar todos los campos.")
            return
        try:
            cliente.send(f"LOGIN:{usuario}:{contrasena}".encode())
            respuesta = cliente.recv(4096).decode()
        except Exception:
            messagebox.showerror("Error", "El servidor no está disponible.")
            return
        if respuesta.startswith("LOGIN_OK:"):  # RF4 - Login exitoso
            token_actual   = respuesta.split(":", 1)[1]
            usuario_actual = usuario
            messagebox.showinfo("Éxito", "Inicio de sesión exitoso.")
            formulario.destroy()
            actualizar_interfaz(True)
        else:  # RF5 - Denegar si credenciales incorrectas
            messagebox.showerror("Error", respuesta)
            password_entry.delete(0, tk.END)

    tk.Button(formulario, text="Iniciar sesión", command=login).pack(pady=20)

# ----------------------------
# RF8 - Envío de mensajes (solo usuarios autenticados)
# RF9 - Límite de 144 caracteres por mensaje
# ----------------------------
def mostrar_formulario_mensaje():
    if not token_actual:  # RF8 - Solo autenticados
        messagebox.showerror("Error", "Debes iniciar sesión para enviar mensajes.")
        return
    if not verificar_conexion():
        return
    formulario = tk.Toplevel(root)
    formulario.title("Enviar Mensaje")
    formulario.geometry("350x220")
    tk.Label(formulario, text="Mensaje (máx. 144 caracteres):").pack(pady=5)
    texto_entry = tk.Text(formulario, height=4, width=40)
    texto_entry.pack(pady=5)

    def enviar():
        texto = texto_entry.get("1.0", tk.END).strip()
        if not texto:
            messagebox.showerror("Error", "El mensaje no puede estar vacío.")
            return
        if len(texto) > 144:  # RF9 - Límite de 144 caracteres
            messagebox.showerror("Error", f"Máximo 144 caracteres (actual: {len(texto)}).")
            return
        try:
            cliente.send(f"MENSAJE:{token_actual}:{texto}".encode())
            respuesta = cliente.recv(4096).decode()
        except Exception:
            messagebox.showerror("Error", "El servidor no está disponible.")
            return
        messagebox.showinfo("Resultado", respuesta)
        formulario.destroy()

    tk.Button(formulario, text="Enviar", command=enviar).pack(pady=10)

# ----------------------------
# RF6 - Cerrar sesión
# ----------------------------
def on_logout_click():
    global usuario_actual, token_actual, cliente
    if token_actual:
        try:
            cliente.send(f"LOGOUT:{token_actual}".encode())
            cliente.recv(4096)
        except Exception:
            pass
    usuario_actual = None
    token_actual   = None
    cliente        = conectar_servidor()
    actualizar_interfaz(False)

# ----------------------------
# RF12 - Interfaz gráfica de usuario
# ----------------------------
def actualizar_interfaz(sesion_iniciada):
    button_login.pack_forget()
    button_register.pack_forget()
    button_mensaje.pack_forget()
    button_logout.pack_forget()
    if sesion_iniciada:
        button_mensaje.pack(pady=10)
        button_logout.pack(pady=10)
    else:
        button_login.pack(pady=10)
        button_register.pack(pady=10)

button_login    = tk.Button(root, text="Iniciar sesión", command=on_login_click)
button_register = tk.Button(root, text="Registrarse",   command=on_register_click)
button_mensaje  = tk.Button(root, text="Enviar Mensaje", command=mostrar_formulario_mensaje)
button_logout   = tk.Button(root, text="Cerrar sesión",  command=on_logout_click)

actualizar_interfaz(False)
root.mainloop()

try:
    cliente.close()
except Exception:
    pass
