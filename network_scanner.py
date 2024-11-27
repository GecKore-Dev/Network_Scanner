import socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import netifaces
import requests
import platform
import re
import os
import threading
import csv
from fpdf import FPDF
from PIL import Image, ImageTk
import sys

# Signature du script
"""
 _____           _   __               
|  __ \         | | / /               
| |  \/ ___  ___| |/ /  ___  _ __ ___ 
| | __ / _ \/ __|    \ / _ \| '__/ _ \
| |_ \ \  __/ (__| |\  \ (_) | | |  __/
 \____/\___|\___\_| \_/\___/|_|  \___|
                                      
Nom du fichier : network_scanner.py
Version       : 1.0.0
Auteur        : GecKore-Dev
GitHub        : https://github.com/GecKore-Dev
"""

# Variables globales
stop_scan = False
scan_results = []

# Définir les chemins pour les ressources
def resource_path(relative_path):
    """Obtenir le chemin absolu pour les fichiers inclus dans l'exécutable."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

logo_path = resource_path("C:/KRIS/Cassis_Doc-SpaceVSC/Projet_Portfolio-script/Network_Scanner/asset/Logo-GecKore.png")
icon_path = resource_path("C:/KRIS/Cassis_Doc-SpaceVSC/Projet_Portfolio-script/Network_Scanner/asset/Icon-GecKore.ico")
pdf_banner_path = resource_path("C:/KRIS/Cassis_Doc-SpaceVSC/Projet_Portfolio-script/Network_Scanner/asset/recap_scan.png")


def get_local_info():
    """Récupère les informations locales du réseau."""
    try:
        gws = netifaces.gateways()
        default_iface = gws['default'][netifaces.AF_INET][1]
        iface_details = netifaces.ifaddresses(default_iface)
        local_ip = iface_details[netifaces.AF_INET][0]['addr']
        netmask = iface_details[netifaces.AF_INET][0]['netmask']
        mac_address = iface_details[netifaces.AF_LINK][0]['addr']

        hostname = socket.gethostname()
        local_dns = socket.getfqdn()
        dns_suffix = local_dns.split('.', 1)[-1] if '.' in local_dns else "Non défini"

        dns_servers = []
        system_name = platform.system()
        if system_name == "Windows":
            import subprocess
            result = subprocess.run("ipconfig /all", capture_output=True, text=True, shell=True)
            for line in result.stdout.splitlines():
                if "DNS Servers" in line or "Serveurs DNS" in line:
                    dns_servers.append(line.split(":")[-1].strip())
                elif line.strip() and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line.strip()):
                    dns_servers.append(line.strip())
        else:
            try:
                with open("/etc/resolv.conf") as resolv_file:
                    dns_servers = [line.split()[1] for line in resolv_file if line.startswith("nameserver")]
            except FileNotFoundError:
                dns_servers = ["Non disponible"]

        dns_servers = list(dict.fromkeys(dns_servers))
        dns_servers = ", ".join(dns_servers) if dns_servers else "Non disponible"

        ipv6_address = iface_details.get(netifaces.AF_INET6, [{'addr': 'Non disponible'}])[0]['addr']
        public_ip = requests.get('https://api.ipify.org').text

        return {
            "IP Locale": local_ip,
            "Masque de sous-réseau": netmask,
            "Passerelle": gws['default'][netifaces.AF_INET][0],
            "Serveurs DNS": dns_servers,
            "Hostname": hostname,
            "Suffixe DNS": dns_suffix,
            "Adresse IPv6": ipv6_address,
            "MAC": mac_address,
            "IP Publique": public_ip
        }
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur lors de la récupération des informations : {e}")
        return {}


def display_local_info():
    """Affiche les informations locales dans le widget texte."""
    global info_text
    info = get_local_info()
    if not info:
        return

    data = (
        f"IP Locale : {info['IP Locale']}\n"
        f"Masque de sous-réseau : {info['Masque de sous-réseau']}\n"
        f"Passerelle : {info['Passerelle']}\n"
        f"Serveurs DNS : {info['Serveurs DNS']}\n"
        f"Hostname : {info['Hostname']}\n"
        f"Suffixe DNS : {info['Suffixe DNS']}\n"
        f"{'-' * 16}\n"
        f"Adresse IPv6 : {info['Adresse IPv6']}\n"
        f"MAC : {info['MAC']}\n"
        f"{'-' * 16}\n"
        f"IP Publique : {info['IP Publique']}\n"
    )

    info_text.delete(1.0, tk.END)
    info_text.insert(tk.END, data)
    lines = len(data.splitlines())
    char_width = max(len(line) for line in data.splitlines())
    info_text.config(width=char_width, height=lines + 1)


def get_default_ip_range():
    """Récupère la plage IP par défaut basée sur l'adresse IP locale."""
    try:
        gws = netifaces.gateways()
        default_iface = gws['default'][netifaces.AF_INET][1]
        iface_details = netifaces.ifaddresses(default_iface)
        local_ip = iface_details[netifaces.AF_INET][0]['addr']
        network_prefix = ".".join(local_ip.split(".")[:-1])
        return f"{network_prefix}.1-254"
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de récupérer la plage IP par défaut : {e}")
        return "192.168.1.1-254"


def scan_host(ip, ports_to_scan):
    """Scanne un hôte spécifique pour détecter les ports ouverts."""
    open_ports = []
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Non résolu"
    
    for port in ports_to_scan:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return hostname, open_ports


def scan_network(ip_range):
    """Scanne la plage IP spécifiée pour détecter les hôtes actifs et leurs ports ouverts."""
    global stop_scan, scan_results
    results = []
    try:
        network_prefix = ".".join(ip_range.split(".")[:-1])
        start_ip, end_ip = map(int, ip_range.split(".")[-1].split("-"))
        ports_to_scan = [22, 80, 443, 21, 23, 25, 110, 8080]

        for i in range(start_ip, end_ip + 1):
            if stop_scan:
                break
            ip = f"{network_prefix}.{i}"
            results_text.insert(tk.END, f"En cours : {ip}...\n")
            results_text.update_idletasks()
            response = os.system(f"ping -n 1 -w 500 {ip} >nul")
            if response == 0:
                hostname, open_ports = scan_host(ip, ports_to_scan)
                results.append((ip, hostname, open_ports))
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur lors du scan : {e}")
    scan_results = results
    return results


def display_scan_results(ip_range):
    """Lance le scan réseau et affiche les résultats."""
    global stop_scan, scan_results
    stop_scan = False
    results_text.delete(1.0, tk.END)
    results_text.insert(tk.END, f"Scan en cours pour la plage : {ip_range}...\n")

    def scan_and_display():
        results = scan_network(ip_range)
        if not stop_scan:
            results_text.insert(tk.END, f"{'-'*40}\nRécapitulatif :\n")
            if results:
                for ip, hostname, open_ports in results:
                    results_text.insert(tk.END, f"IP : {ip}\nHostname : {hostname}\nPorts ouverts : {', '.join(map(str, open_ports))}\n{'-'*40}\n")
            else:
                results_text.insert(tk.END, "Aucun appareil détecté.\n")
        else:
            results_text.insert(tk.END, "Scan interrompu par l'utilisateur.\n")

    threading.Thread(target=scan_and_display, daemon=True).start()


def stop_network_scan():
    """Stoppe un scan réseau en cours."""
    global stop_scan
    stop_scan = True


def clear_scan_results():
    """Efface les résultats du scan réseau."""
    results_text.delete(1.0, tk.END)


def export_scan_results():
    """Exporte les résultats du scan dans un fichier texte, CSV ou PDF."""
    if not scan_results:
        messagebox.showwarning("Attention", "Aucun résultat à exporter.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Fichiers texte", "*.txt"), ("Fichiers CSV", "*.csv"), ("Fichiers PDF", "*.pdf")])
    if not file_path:
        return

    if file_path.endswith(".txt"):
        with open(file_path, "w") as file:
            # Ajout de l'en-tête spécifique pour le fichier TXT
            file.write(
                " _____           _   __               \n"
                "|  __ \\         | | / /               \n"
                "| |  \\/ ___  ___| |/ /  ___  _ __ ___ \n"
                "| | __ / _ \\/ __|    \\ / _ \\| '__/ _ \\\n"
                "| |_\\ \\  __/ (__| |\\  \\ (_) | | |  __/\n"
                " \\____/\\___|\\___\\_| \\_/\\___/|_|  \\___|\n"
                "                                      \n"
                "Nom du fichier : keylogger.py\n"
                "Version       : 1.0.0\n"
                "Auteur        : GecKore-Dev\n"
                "GitHub        : https://github.com/GecKore-Dev\n\n"
            )
            file.write("Récapitulatif des résultats de scan :\n")
            file.write(f"{'-'*40}\n")
            for ip, hostname, open_ports in scan_results:
                file.write(f"IP : {ip}\nHostname : {hostname}\nPorts ouverts : {', '.join(map(str, open_ports))}\n{'-'*40}\n")
        messagebox.showinfo("Succès", f"Résultats exportés avec succès dans {file_path}")

    elif file_path.endswith(".csv"):
        with open(file_path, "w", newline="") as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(["IP", "Hostname", "Ports Ouverts"])
            for ip, hostname, open_ports in scan_results:
                csvwriter.writerow([ip, hostname, ", ".join(map(str, open_ports))])
        messagebox.showinfo("Succès", f"Résultats exportés avec succès dans {file_path}")

    elif file_path.endswith(".pdf"):
        class CustomPDF(FPDF):
            def header(self):
                """En-tête avec l'image sur chaque page."""
                self.image("C:/Users/adm.planche/Downloads/Professional LinkedIn Banner.png", x=10, y=8, w=190)
                self.ln(35)  # Décaler pour le contenu

            def footer(self):
                """Pied de page avec informations et numéro de page."""
                self.set_y(-15)
                self.set_font("Arial", size=10)
                self.cell(0, 10, f"Scanneur de réseau by GecKore | Résultat du Scan | Page {self.page_no()}", align="C")

        pdf = CustomPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Espacement après l'en-tête
        pdf.ln(10)

        # Ajouter les résultats
        for ip, hostname, open_ports in scan_results:
            pdf.cell(0, 10, txt=f"IP : {ip}", ln=True)
            pdf.cell(0, 10, txt=f"Hostname : {hostname}", ln=True)
            pdf.cell(0, 10, txt=f"Ports ouverts : {', '.join(map(str, open_ports))}", ln=True)
            pdf.ln(5)  # Espacement entre chaque résultat

        pdf.output(file_path)
        messagebox.showinfo("Succès", f"Résultats exportés avec succès dans {file_path}")



def create_gui():
    """Crée l'interface graphique."""
    root = tk.Tk()
    root.title("Simulateur de Réseau")
    root.geometry("800x800")
    root.iconbitmap(icon_path)  # Ajouter l'icône

    # Ajouter le logo
    try:
        img = Image.open(logo_path)
        img = img.resize((150, 150), Image.Resampling.LANCZOS)
        logo = ImageTk.PhotoImage(img)
        logo_label = tk.Label(root, image=logo)
        logo_label.image = logo
        logo_label.pack(pady=10)
    except Exception as e:
        print(f"Erreur lors du chargement du logo : {e}")
        messagebox.showerror("Erreur", f"Impossible de charger le logo : {e}")

    # Informations locales
    local_info_frame = ttk.LabelFrame(root, text="Informations Locales")
    local_info_frame.pack(fill="x", padx=10, pady=10)

    global info_text
    info_text = tk.Text(local_info_frame, wrap="word", font=("Arial", 12), height=10)
    info_text.pack(fill="both", expand=True, padx=10, pady=10)

    buttons_frame_local = tk.Frame(local_info_frame)
    buttons_frame_local.pack(pady=5)
    tk.Button(buttons_frame_local, text="Afficher les Infos Locales", command=display_local_info).pack(side="left", padx=5)
    tk.Button(buttons_frame_local, text="Effacer les Infos", command=lambda: info_text.delete(1.0, tk.END)).pack(side="left", padx=5)


    # Scan réseau
    scan_frame = ttk.LabelFrame(root, text="Scan Réseau")
    scan_frame.pack(fill="both", expand=True, padx=10, pady=10)

    ip_range_label = tk.Label(scan_frame, text="Plage IP à scanner (par ex. 192.168.1.1-254) :", font=("Arial", 12))
    ip_range_label.pack(pady=5)

    ip_range_var = tk.StringVar(value=get_default_ip_range())
    ip_range_entry = ttk.Entry(scan_frame, textvariable=ip_range_var, font=("Arial", 12), width=40)
    ip_range_entry.pack(pady=5)

    buttons_frame_scan = tk.Frame(scan_frame)
    buttons_frame_scan.pack(pady=10)
    tk.Button(buttons_frame_scan, text="Lancer le Scan", command=lambda: display_scan_results(ip_range_var.get()), bg="green", fg="white", font=("Arial", 12)).pack(side="left", padx=5)
    tk.Button(buttons_frame_scan, text="Arrêter le Scan", command=stop_network_scan, bg="red", fg="white", font=("Arial", 12)).pack(side="left", padx=5)
    tk.Button(buttons_frame_scan, text="Effacer les Résultats", command=clear_scan_results, bg="orange", fg="white", font=("Arial", 12)).pack(side="left", padx=5)
    tk.Button(buttons_frame_scan, text="Exporter les Résultats", command=export_scan_results, bg="blue", fg="white", font=("Arial", 12)).pack(side="left", padx=5)

    global results_text
    results_text = tk.Text(scan_frame, wrap="word", font=("Arial", 12), height=20)
    results_text.pack(fill="both", expand=True, padx=10, pady=10)

    root.mainloop()


if __name__ == "__main__":
    create_gui()