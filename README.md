# IndividualProject SSH Protocol
SSH Protocol | Client-Server Encrypted Chat with OpenSSL

# Compile command on the server
gcc -Wall -o ssl-server server.c -L/usr/lib -lssl -lcrypto

# Server run command
sudo ./ssl-server 443

# Compile command on the client
gcc -Wall -o ssl-client client.c -L/usr/lib -lssl -lcrypto

# Client run command
./ssl-client 192.168.56.103 443
