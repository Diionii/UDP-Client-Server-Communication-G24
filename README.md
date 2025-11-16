UDP File Server & Client
Një sistem server-client bazuar në UDP për menaxhimin e file-ve me autentifikim dhe privilegje të ndryshme.

🚀 Veçoritë
Serveri
Komunikim UDP me menaxhim të klientëve të shumtë

Sistem autentifikimi me role (admin/user)

Komanda të avancuara për menaxhim file-sh

Monitorim në kohë reale me statistika

Logging i plotë i aktivitetit

Cleanup automatik për klientët jo-aktiv

Siguri kundër path traversal attacks

Klienti
Ndërfaqe command-line e thjeshtë

Support për upload/download të file-ve

Timeout i konfigurueshëm bazuar në rol

Komanda të ndara për admin dhe user

📋 Komandat e Suportuara
Për të gjithë përdoruesit:
/login <username> [token] - Identifikohu në sistem

/list [directory] - Listo file-t në një direktori

/read <filename> - Lexo përmbajtjen e një file-i

/exit - Dil nga sistemi

Vetëm për Administratorët:
/upload <local_file> - Ngarko file nga klienti në server

/download <server_file> [local_name] - Shkarko file nga serveri

/delete <filename> - Fshi file nga serveri

/search <directory> <keyword> - Kërko tekst në file

/info <filename> - Shfaq informacion të detajuar për file

🔧 Instalimi dhe Ekzekutimi
Për Serverin:
bash
# Kompilimi (në Windows me MinGW)
gcc -o server server.c -lws2_32

# Ekzekutimi
server.exe [port] [bind_ip]

# Shembull:
server.exe 9000 0.0.0.0
Për Klientin:
bash
# Kompilimi
gcc -o client client.c -lws2_32

# Ekzekutimi  
client.exe <server_ip> <port>

# Shembull:
client.exe 127.0.0.1 9000
⚙️ Konfigurimi
Serveri:
Port default: 9000

Bind IP default: 0.0.0.0 (të gjitha interfacet)

Max clients: 100

Upload max size: 10MB

Inactivity timeout: 5 minuta

Admin token: "secret_admin_token"

Klienti:
Timeout për admin: 10 sekonda

Timeout për user: 30 sekonda

Chunk size: 64500 bytes

Në file:
server_log.txt - Logu i të gjitha operacioneve

server_stats.txt - Statistikat periodike

🛡️ Siguria
Path validation - Parandalon path traversal attacks

Size limits - Kufizon madhësinë e upload-imeve

Admin verification - Verifikon privilegjet për komanda sensitive

Session management - Menaxhon kohën e sesioneve