# Crypt0n v2.1 - Bot Discord per Cybersecurity

Crypt0n è un bot Discord avanzato progettato per analisi di sicurezza informatica, OSINT, monitoraggio e moderazione server, con supporto per traduzioni in oltre 130 lingue tramite Google Translate.

## Funzionalità
- **Analisi Avanzata**: Traceroute, analisi SSL/TLS, enumerazione subdomini, geolocalizzazione IP, rilevazione tecnologie web, analisi robots.txt.
- **Analisi Forense**: Calcolo hash multipli, verifica integrità file, generazione chiavi RSA.
- **Intelligenza Minacce**: Analisi rischi IP, controllo liste nere, feed minacce in tempo reale (AlienVault OTX).
- **OSINT**: Ricerca profili social.
- **Monitoraggio**: Monitoraggio cambiamenti siti web con frequenza personalizzabile.
- **Comandi Base**: Informazioni IP, DNS lookup, WHOIS, hash, codifica/decodifica Base64, generazione password, analisi header, verifica email, scan porte, analisi URL, forza password, notizie cybersecurity, controllo leak, analisi metadati, cifratura/decifratura AES, scansione malware.
- **Moderazione**: Ban, kick, protezione antiraid con log.
- **Utilità**: Traduzioni multilingua, prefisso personalizzabile per server, avatar con effetti grafici, info utente/server, inviti, crediti.

## Prerequisiti
- Python 3.8+
- Npcap (Windows) o libpcap (Linux/macOS) per il comando `$traceroute`:
  - Windows: Scarica [Npcap](https://npcap.com/#download).
  - Linux: `sudo apt-get install libpcap0.8-dev`
  - macOS: `brew install libpcap`

## Installazione
1. Clona la repository:
   ```bash
   git clone https://github.com/4l-alex/Crypt0n.git 
   cd crypt0n

2. Installa le dipendenze:
   ```bash
   pip install -r requirements.txt

3. Crea un file .env con:
DISCORD_TOKEN=tuo_token
VIRUSTOTAL_API_KEY=tua_chiave
ABUSEIPDB_API_KEY=tua_chiave
HIBP_API_KEY=tua_chiave
OTX_API_KEY=tua_chiave

Ottieni le chiavi da:
Discord Developer Portal
VirusTotal
AbuseIPDB
HaveIBeenPwned
AlienVault OTX

4. Avvia il bot.
  ```bash
  python bot.py
