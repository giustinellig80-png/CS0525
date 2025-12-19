import socket       # Modulo per le connessioni di rete
import datetime     # Per ottenere l'orario attuale della scansione
import os           # Per interagire con il sistema operativo (es. ping)
import sys          # Per gestire l'uscita dallo script (sys.exit)
import ipaddress    # Per validare che l'input sia un vero indirizzo IP


# Definiamo la larghezza fissa delle colonne per disegnare la tabella ASCII
Width_PORT = 7          # Larghezza colonna Porta
Width_SERV = 15         # Larghezza colonna Servizio
Width_RISK = 60         # Larghezza colonna Rischio

# DIZIONARIO DEI RISCHI 
RISCHI = {
    21: "ALTO: FTP (Non criptato, sniffabile)",
    22: "MEDIO: SSH (Rischio Brute Force)",
    23: "CRITICO: Telnet (Non criptato, obsoleto)",
    25: "MEDIO: SMTP (Possibile Open Relay)",
    53: "MEDIO: DNS (Rischio DDoS Amplification)",
    80: "BASSO: HTTP (Non criptato)",
    110: "ALTO: POP3 (Password in chiaro)",
    135: "ALTO: RPC (Enumerazione)",
    139: "ALTO: NetBIOS (Info Leak)",
    143: "ALTO: IMAP (Password in chiaro)",
    443: "INFO: HTTPS (Verificare Web App)",
    445: "CRITICO: SMB (Rischio Ransomware/Worm)",
    3306: "ALTO: MySQL (Non esporre su Internet)",
    3389: "CRITICO: RDP (Rischio accesso remoto)",
    5900: "ALTO: VNC (Spesso senza password)",
    8080: "MEDIO: Proxy/Web Alt"
}


while True:
    try:
        # Richiede l'IP all'utente e rimuove spazi vuoti (.strip)
        input_string = input("Inserisci l'IP target (es. 192.168.1.1): ").strip()
        # Converte la stringa in oggetto IP; se fallisce, solleva un errore
        ip_obj = ipaddress.ip_address(input_string)
        target_ip = str(ip_obj)
        break  # Esce dal ciclo se l'IP è valido
    except ValueError:
        print("[!] ERRORE: Devi inserire un IP valido.")


while True:
    try:
        # Richiede le porte di inizio e fine scansione
        start_port = int(input("Inserisci porta di partenza: "))
        end_port = int(input("Inserisci porta di fine: "))
        
        # Controllo logico: l'inizio non può essere maggiore della fine
        if start_port > end_port:
            print("[!] La porta di partenza deve essere minore della porta di fine.")
            continue # Ricomincia il ciclo
        break # Esce dal ciclo se i numeri sono validi
    except ValueError:
        print("[!] Errore: Devi inserire dei numeri interi.")

file_report = "report_scansione.txt" # Nome del file di output


def host_up(ip):
    #Verifica se l'host è online inviando un pacchetto ICMP (Ping)
    print(f"\n[*] Verifica raggiungibilità di {ip} in corso...")
    # Esegue il ping: -c 1 (un pacchetto), -W 1 (timeout 1 sec)
    # > /dev/null nasconde l'output del comando ping
    response = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
    # Se response è 0, il ping ha avuto successo (Host Online)
    return True if response == 0 else False

def get_service_name(port):
    #Ottiene il nome del servizio standard per una data porta
    try:
        name = socket.getservbyport(port)
        # Taglia il nome se è troppo lungo per non rompere la tabella
        return name[:Width_SERV-2] 
    except:
        return "sconosciuto" # Se non trova il nome, restituisce default

def get_ris_info(port):
    #Recupera la descrizione del rischio 
    # .get(chiave, default) restituisce il valore o il default se non esiste
    return RISCHI.get(port, "GENERICO (Superficie di attacco)")

def build_line(char='-'):
    #Crea una linea orizzontale separatrice per la tabella
    # Moltiplica il carattere per la larghezza delle colonne + bordi
    return f"+{char * (Width_PORT + 2)}+{char * (Width_SERV + 2)}+{char * (Width_RISK + 2)}+"

def form_row(port, service, risk):
    #Formatta una singola riga di dati allineando il testo
    # <{Width} allinea il testo a sinistra occupando tot spazi
    return f"| {str(port):<{Width_PORT}} | {service:<{Width_SERV}} | {risk:<{Width_RISK}} |"


def scan_ports():
    # 1. Controlla se l'host è vivo prima di scansionare
    if not host_up(target_ip):
        print(f"\n[!] ERRORE CRITICO: L'IP {target_ip} non è raggiungibile.")
        sys.exit() # Interrompe lo script
    else:
        print(f"[*] Host {target_ip} è ONLINE. Inizio scansione...")

    print(f"\nAVVIO SCANSIONE...")
    
    # Prepara le stringhe per l'intestazione della tabella
    header_line = build_line('=')
    sep_line = build_line('-')
    header_text = form_row("PORTA", "SERVIZIO", "RISCHIO RILEVATO")
    
    # Stampa l'intestazione a schermo
    print(header_line)
    print(header_text)
    print(header_line)

    # Apre il file in modalità "append" (aggiunge senza sovrascrivere)
    with open(file_report, "a") as f:
        # Scrive data e ora nel file
        f.write(f"\n--- SCANSIONE: {target_ip} [{datetime.datetime.now()}] ---\n")
        f.write(header_line + "\n")
        f.write(header_text + "\n")
        f.write(header_line + "\n")
        
        # Ciclo principale: itera su ogni porta nel range specificato
        for port in range(start_port, end_port + 1):
            # Crea un socket IPv4 (AF_INET) TCP (SOCK_STREAM)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5) # Imposta timeout breve (0.5 sec) per velocità
            
            # Tenta la connessione. Restituisce 0 se (Porta Aperta)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                # Se aperta, raccoglie le informazioni
                service = get_service_name(port)
                risk = get_ris_info(port)
                
                # Formatta la riga per la tabella
                row = form_row(port, service, risk)
                
                # Stampa sul terminale e su file
                print(row)
                print(sep_line) 
                f.write(row + "\n")
                f.write(sep_line + "\n")
                
            # Chiude il socket 
            sock.close()

    print(f"\n--- SCANSIONE COMPLETATA ---")

# Avvia la funzione principale
scan_ports()