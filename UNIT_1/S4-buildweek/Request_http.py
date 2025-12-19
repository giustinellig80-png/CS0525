# Importiamo la libreria 'requests' per gestire le richieste Web (HTTP).
# Importiamo la libreria requests per gestire le richieste Web (HTTP).
import requests
# Importiamo datetime per il timestamp nel report.
import datetime

# Chiediamo all'utente l'indirizzo web (URL) completo da analizzare.
target_path = input("Inserisci il path target : ")
# Nome del file dove salvare i risultati.
file_report = "report_scansione.txt"

# Funzione principale .
def check_http_methods():
    # Messaggi informativi a video.
    print(f" \n ANALISI VERBI HTTP SU: {target_path} \n ")
    
    # Lista dei comandi (verbi) HTTP che vogliamo testare.
    verbs = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD']
    # Lista vuota per memorizzare quali metodi troveremo attivi.
    enabled_methods = []
    
    # Apriamo il file in modalità append.
    with open(file_report, "a") as r:
        # Scriviamo l'intestazione nel file.
        r.write(f"\n HTTP AUDIT: {target_path} [{datetime.datetime.now()}] \n")
        
        try:
            # Facciamo una richiesta 'HEAD' (solo intestazioni) al server.
            initial_req = requests.head(target_path,  timeout=5)
            
            # Cerchiamo l'header 'Server' (es. Apache/2.2) nella risposta.
            server_software = initial_req.headers.get('Server', 'Nascosto')
            # Cerchiamo l'header 'X-Powered-By' (es. PHP/5.3).
            powered_by = initial_req.headers.get('X-Powered-By', 'Non dichiarato')
            
            # Prepariamo il messaggio con le info trovate.
            info_msg = f"- -  TECNOLOGIA RILEVATA: Server={server_software} | Backend={powered_by} \n"
            
            print(info_msg)          # Stampa sul terminale
            r.write(info_msg + "\n") # Scrive sul file
            
        except:
            # Se il server è spento o irraggiungibile, stampiamo un errore.
            print(" Impossibile contattare il server per info base.")

        
        for verb in verbs:
            try:
                # Eseguiamo la richiesta HTTP usando il verbo corrente della lista.
                response = requests.request(verb, target_path, timeout=5)
                
                # Otteniamo la descrizione testuale (es. "OK", "Method Not Allowed").
                reason_text = response.reason 
                # Leggiamo la dimensione della risposta in byte.
                length = response.headers.get('Content-Length', '0')
                
                # Se il codice di risposta NON è 405, il metodo è attivo.
                if response.status_code != 405:
                    
                    # Creiamo il messaggio di successo (ABILITATO).
                    message = f"[+] Metodo {verb}: ABILITATO (Stato: {response.status_code} [{reason_text}], Size: {length} bytes)"
                    
                    # Aggiungiamo il metodo alla lista dei metodi trovati.
                    enabled_methods.append(f" {verb} ({response.status_code})")
                
                else:
                    # Se è 405, il metodo è DISABILITATO. 
                    message = f"[-] Metodo {verb}: DISABILITATO (Stato: {response.status_code} [{reason_text}])"

                
                print(message)          # stampa metodi sul terminale 
                r.write(message  + "\n") # stampa metodi sul file

            except requests.exceptions.RequestException as e:
                # Gestione errori (es. il timeout di rete).
                err = f"[!] Errore su {verb}: {e}"
                print(err)
                r.write(err + "\n")

        
        # Creiamo il riassunto finale della lista (solo quelli abilitati).
        summary = f"\n RIASSUNTO METODI ATTIVI: {enabled_methods} "
        
        print(summary)          
        r.write(summary + "\n") 
        
    
    print(f"\n ANALISI COMPLETATA ")

# Chiamiamo la funzione per avviare lo script.
check_http_methods()