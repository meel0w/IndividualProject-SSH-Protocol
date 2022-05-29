#include <stdio.h> //Standard input and output
#include <string.h> //Using fgets funtions for geting input from user
#include <errno.h> //Use to find error in library
#include <unistd.h> //Use of fork to receive and send message
#include <malloc.h> //Use for memory allocation
#include <sys/socket.h> //Use to create sockets
#include <resolv.h> //Server to find IP address
#include <netdb.h> //Definitions for network database operations 
#include <openssl/ssl.h> //To use OpenSSL function
#include <openssl/err.h> // To find error in OpenSSL 
#define FAIL    -1 //For error output == -1 
#define BUFFER  2048  //Buffer to read message


int OpenConnection(const char *hostname, int port)
{   
    int sd;

	struct hostent *host;

	struct sockaddr_in addr;   //Creating the sockets

	if ( (host = gethostbyname(hostname)) == NULL )
	{
	    perror(hostname);

	    abort();
	}

	sd = socket(PF_INET, SOCK_STREAM, 0);   // Setting the connection as tcp. It creates endpoint for connection 

	bzero(&addr, sizeof(addr));

	addr.sin_family = AF_INET;

	addr.sin_port = htons(port);

	addr.sin_addr.s_addr = *(long*)(host->h_addr);

	if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )  //Initiate a connection on a socket
	{
	    close(sd);

	    perror(hostname);

	    abort();
	}

	return sd;

}

SSL_CTX* InitCTX(void)   //Creating and setting up ssl context structure
{   
    SSL_METHOD *method;

	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();  //Load cryptos and others 

	SSL_load_error_strings();   // Bring in and register error messages 

	method = TLSv1_2_client_method();  // Create new client-method instance 

	ctx = SSL_CTX_new(method);   // Create new context 

	if ( ctx == NULL )
	{
	    ERR_print_errors_fp(stderr);

	    abort();
	}

	return ctx;
}

void ShowCerts(SSL* ssl)  //Show the ceritficates to server and match them but here we will not using any client certificate
{   
    X509 *cert;

	char *line;

	cert = SSL_get_peer_certificate(ssl); // Get the server's certificate 

	if ( cert != NULL )
	{
	    printf("Server certificates:\n");

	    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);

	    printf("Subject: %s\n", line);

	    free(line);       // Free the malloc'ed string 

	    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

	    printf("Issuer: %s\n", line);

	    free(line);       // Free the malloc'ed string 

	    X509_free(cert);     // Free the malloc'ed certificate copy 
	}

	else
	    printf("Info: No client certificates configured.\n");
}

int main(int count, char *strings[])   // Getting port and ip as an argument
{   
    SSL_CTX *ctx;

	int server;

	SSL *ssl;

	char buf[1024];

	char input[BUFFER];

	int bytes;

	char *hostname, *portnum;

	pid_t cpid;     // Fork variable

	if ( count != 3 )
	{
	    printf("usage: %s  \n", strings[0]);

	    exit(0);
	}

	SSL_library_init();   //Load encryption and hash algo's in ssl

	hostname=strings[1];

	portnum=strings[2];

	ctx = InitCTX();

	server = OpenConnection(hostname, atoi(portnum));   //Converting ascii port to integer 

	ssl = SSL_new(ctx);      // Create new SSL connection state 

	SSL_set_fd(ssl, server);    // Attach the socket descriptor 

	if ( SSL_connect(ssl) == FAIL )   // Perform the connection 
        ERR_print_errors_fp(stderr);

	else
	{    
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

	    ShowCerts(ssl);

	    // Get any certs 

	    cpid=fork();

	    //Fork system call is used to create a new process

	    if(cpid==0)
	    {

	        while(1)
            {
	            printf("\nMESSAGE TO SERVER:");

	            fgets(input, BUFFER, stdin);

	            SSL_write(ssl, input, strlen(input));   // Encrypt & send message 
            }
        }

	    else 
        {
	        while(1)
	        {
	            bytes = SSL_read(ssl, buf, sizeof(buf)); // Get request 

	            if ( bytes > 0 )
	            { 
	                buf[bytes] = 0;

	                printf("\nMESSAGE FROM SERVER: %s\n", buf);
                }
	        } 
        }

	    SSL_free(ssl);        // Release connection state 
	}   
    
    close(server);         // Close the sockets 

	SSL_CTX_free(ctx);        // Release context 

	return 0;
}