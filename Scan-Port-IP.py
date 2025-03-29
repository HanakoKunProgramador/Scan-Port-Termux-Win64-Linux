import os
import socket
import threading
from colorama import Fore, Style, init

# Inicializa Colorama
init(autoreset=True)

# Función para mostrar el dragón en ASCII
def mostrar_dragon():
    dragon_ascii = r"""
             __====-_  _-====__
      _--^^^#####//      \\#####^^^--_
   _-^##########// (    ) \\##########^-_
  -############//  |\^^/|  \\############-
 -#############//   (@::@)   \\#############-
-###############\\    \\//    //###############-
-#################\\  (oo)  //#################-
-###################\\//  \\//###################-
_#/|##########\\######(    )######//##########|\#_
|/ |#/\#/\#/\/  \\#/\##\\  //##/\#/\/#/\#/\#| \
  |/  V  V  V    V  V  V    V  V  V  V  V  V  \
"""
    print(Fore.MAGENTA + dragon_ascii)

# Función para mostrar el menú
def mostrar_menu():
    opciones = [
        "1. Ver la IP de la PC",
        "2. Escanear puertos de una IP",
        "3. Buscar vulnerabilidades en una IP",
        "4. Salir"
    ]

    print(Style.BRIGHT + Fore.CYAN + "\n=== MENÚ ===")
    for opcion in opciones:
        print(Fore.YELLOW + opcion)

def obtener_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

def escanear_puertos(ip, rango):
    abiertos = []
    for puerto in rango:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        resultado = sock.connect_ex((ip, puerto))
        if resultado == 0:
            abiertos.append(puerto)
        sock.close()
    return abiertos

def escaneo_con_hilos(ip, rango):
    abiertos = []
    
    def escanear_puerto(puerto):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        resultado = sock.connect_ex((ip, puerto))
        if resultado == 0:
            abiertos.append(puerto)
        sock.close()

    hilos = []
    for puerto in rango:
        hilo = threading.Thread(target=escanear_puerto, args=(puerto,))
        hilos.append(hilo)
        hilo.start()

    for hilo in hilos:
        hilo.join()

    return abiertos

def detectar_servicio(puerto):
    servicios = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        8080: "HTTP Alternativo",
        6379: "Redis"
    }
    return servicios.get(puerto, "Servicio desconocido")

def buscar_vulnerabilidades(ip):
    vulnerabilidades = {}
    
    puertos_comunes = [21, 22, 23, 25, 53, 80, 443, 3306, 8080, 6379]
    puertos_abiertos = escaneo_con_hilos(ip, puertos_comunes)

    for puerto in puertos_abiertos:
        servicio = detectar_servicio(puerto)
        if servicio:
            vulnerabilidades[puerto] = {
                "servicio": servicio,
                "descripcion": obtener_descripcion_vulnerabilidad(servicio)
            }

    return vulnerabilidades

def obtener_descripcion_vulnerabilidad(servicio):
    descripciones = {
        "FTP": "Puede ser vulnerable a ataques de fuerza bruta y a la transferencia de archivos no seguros.",
        "SSH": "Asegúrate de que esté configurado correctamente para evitar ataques de diccionario.",
        "Telnet": "Inseguro, se recomienda usar SSH. Puede ser vulnerable a ataques de sniffing.",
        "SMTP": "Puede ser vulnerable a ataques de relé y a la inyección de correo.",
        "DNS": "Verifica si está expuesto a ataques de envenenamiento de caché.",
        "HTTP": "Verifica si hay vulnerabilidades en la aplicación web, como inyección SQL o XSS.",
        "HTTPS": "Asegúrate de que la configuración SSL/TLS sea segura y válida.",
        "MySQL": "Asegúrate de que no esté expuesto al público y que tenga una contraseña fuerte.",
        "HTTP Alternativo": "Puede estar ejecutando servicios inseguros o aplicaciones web vulnerables.",
        "Redis": "Asegúrate de que no esté accesible públicamente y que tenga autenticación."
    }
    return descripciones.get(servicio, "No se encontraron vulnerabilidades conocidas.")

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')  # Limpiar la consola
        mostrar_dragon()
        mostrar_menu()

        eleccion = input(Fore.GREEN + "\nElige una opción: ")

        os.system('cls' if os.name == 'nt' else 'clear')  # Limpiar la consola después de la elección

        if eleccion == '1':
            ip = obtener_ip()
            print(Fore.BLUE + f"La dirección IP de la PC es: {ip}")
        elif eleccion == '2':
            ip_a_revisar = input(Fore.GREEN + "Introduce la dirección IP a revisar: ")
            inicio = int(input(Fore.GREEN + "Introduce el puerto de inicio: "))
            fin = int(input(Fore.GREEN + "Introduce el puerto de fin: "))
            rango = range(inicio, fin + 1)

            print(Fore.BLUE + f"Iniciando escaneo de puertos en {ip_a_revisar}...")
            puertos_abiertos = escaneo_con_hilos(ip_a_revisar, rango)

            if puertos_abiertos:
                print(Fore.BLUE + f"Puertos abiertos en {ip_a_revisar}:")
                for puerto in puertos_abiertos:
                    print(Fore.YELLOW + f"Puerto {puerto} está abierto y ejecuta el servicio: {detectar_servicio(puerto)}")
            else:
                print(Fore.RED + f"No se encontraron puertos abiertos en {ip_a_revisar}.")
        elif eleccion == '3':
            ip_a_revisar = input(Fore.GREEN + "Introduce la dirección IP a revisar: ")
            print(Fore.BLUE + f"Buscando vulnerabilidades en {ip_a_revisar}...")
            vulnerabilidades = buscar_vulnerabilidades(ip_a_revisar)

            if vulnerabilidades:
                print(Fore.BLUE + "Vulnerabilidades encontradas:")
                for puerto, info in vulnerabilidades.items():
                    print(Fore.YELLOW + f"Puerto {puerto} ({info['servicio']}): {info['descripcion']}")
            else:
                print(Fore.RED + "No se encontraron vulnerabilidades conocidas en los puertos comunes.")
        elif eleccion == '4':
            print(Fore.RED + "Saliendo del programa...")
            break
        else:
            print(Fore.RED + "Opción no válida. Intenta de nuevo.")

        input(Fore.GREEN + "\nPresiona Enter para volver al menú...")  # Esperar a que el usuario presione Enter

if __name__ == "__main__":
    main()