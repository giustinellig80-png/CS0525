# Importa il modulo socket, necessario per creare connessioni di rete TCP/IP.
import socket
#importiamo struct per convertire i dati binari in dati leggibili.
import struct
# Importa sys per poter chiudere forzatamente il programma (sys.exit) se l'IP non risponde.
import sys
# Importa il modulo datetime per ottenere la data e l'ora attuali per il report.
import datetime

#definiamo il file di salvataggio delle letture.
FILE = "sniffer.txt"

# FUNZIONE PER OTTENERE L'IP LOCALE AUTOMATICAMENTE
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Non invia realmente dati, serve solo per capire quale interfaccia viene usata
        s.connect(('8.8.8.8', 80))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# Impostiamo il target automaticamente
target = get_local_ip()


#definiamo la funzione per data e ora attuali
def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# definiamo una funzione che apre il file in modalità append (aggiunge).
def save_to_file(log):
    try:  
        with open(FILE, "a", encoding="utf-8") as f: # utf-8 per evitare caratteri speciali
            f.write(log + "\n")
    except IOError as e:
        print(f"[!] Errore scrittura file: {e}")

#creazione del socket AF_PACKET (basso livello 2) SOCK_RAW (permette di vedere i pacchetti grezzi inclusi header) ntohs (cattura tutto il traffico eternet)
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except AttributeError:
    #senza i permessi non si può fare l'operazione
    sys.exit("[!] Errore: Richiede permessi di Root (sudo).")

#stampo dello sniffer attivo
print(f"[] Sniffer attivo su {target}.")
print("[] CTRL+C per uscire.")

#dizionario traduce i numeri dei protocolli nei loro nomi
name_protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}

#ciclo vero e proprio. lo sniffer si mette in ascolto.
try:
    while True:
        # variabile che contiene i dati del pacchetto (buffer massimo)
        raw, _ = s.recvfrom(65535)
        
        # si analizza per capire il tipo di protocollo (2048 nello standard eternet il pacchetto contiene dati IPV4)
        if struct.unpack('!H', raw[12:14])[0] != 2048:
            continue

        # raw 14 rappresenta il primo byte del header, "la & 15" ci permette di prendere gli ultimi 4 bit 
        #lunghezza dell'internet header, abbiamo moltiplicato per 4 perchè la lunghezza deve essere 32 bit, così da ottenere i byte totali del header ip
        ihl = (raw[14] & 15) * 4
        # estrae ip sorgente byte
        src = socket.inet_ntoa(raw[26:30])
        # estrae ip destinazione byte
        dst = socket.inet_ntoa(raw[30:34])

        # si analizza il pacchetto solo se l'ip target è il mittente o il destinatario
        if target == src or target == dst:
            p_num = raw[23] # numero protocollo
            p_name = name_protocol.get(p_num, "ALTRO") # col dizionario otteniamo il nome del protocollo, se non è uno dei 3 protocolli scrive "altro"

            extra_info = "" 
            
            #se il protocollo è TCP o UDP entra nel ciclo
            if p_num in (6, 17):

                #calcoliamo dove inizia il segmento TCP/UDP
                t_start = 14 + ihl

                # estrae le porte, prende 4 byte 2 dalla porta sorgente 2 dalla porta di destinazione
                sport, dport = struct.unpack('!HH', raw[t_start:t_start+4])

                # mostra a schermo le porte trovate
                extra_info = f"| Porte: {sport} -> {dport}"
            
            # la stringa che salva e stampa (len raw per la grandezza del pacchetto in byte)
            log_line = f"[{get_timestamp()}] [{p_name}] {src} -> {dst} {extra_info} | Size: {len(raw)} bytes"
            
            #stampa sul terminale
            print(log_line)
            
            #salva sul file txt
            save_to_file(log_line)

except KeyboardInterrupt:
    #se premi control + c avverte che chiude il programma
    print("\n[!] Stop. File di log chiuso.")