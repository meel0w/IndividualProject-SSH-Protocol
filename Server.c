#include <stdio.h> //Standard input and output
#include <string.h> //Using fgets funtions for geting input from user
#include <errno.h> //Use to find error in library
#include <unistd.h> //Use of fork to receive and send message
#include <malloc.h>  //Use for memory allocation 
#include <sys/socket.h>  //To create sockets
#include <sys/types.h>  //To use sockets
#include <arpa/inet.h>  // Ascii bit to Network bit
#include <netinet/in.h>   // Network bit to Ascii bit 
#include <resolv.h>  //Server to find out the IP address
#include <openssl/ssl.h> //To use OpenSSL function
#include <openssl/err.h> // To find error in OpenSSL
#define FAIL    -1 //For error output == -1 
#define BUFFER  2048  //Buffer to read message


int OpenListener(int port)   
{   
    int sd;

	struct sockaddr_in addr;   //Creating the sockets

	sd = socket(PF_INET, SOCK_STREAM, 0);

	bzero(&addr, sizeof(addr));    //Free output the garbage space in memory

	addr.sin_family = AF_INET;    //Getting ip address from the machine 

	addr.sin_port = htons(port);   // Converting host bit to network bit 

	addr.sin_addr.s_addr = INADDR_ANY;

	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) // Assigning the ip address and port
	{
		perror("can't bind port");    // Reporting error using errno.h library 

		abort();      //If there are error then abort the process 
	}

	if ( listen(sd, 10) != 0 )     //For listening to max of 10 clients in the queue
	{
		perror("Can't configure listening port");  // Reporting error using errno.h library 

		abort();      //If there are error then abort the process 
	}

	return sd;

}

	
int isRoot()        //For checking if the root user is executing the server
{
	if (getuid() != 0)    
	{
		return 0;
	}

	else
	{
		return 1;       // If root user is not executing report must be user 
	}
}

SSL_CTX* InitServerCTX(void)      //Creating and setting up ssl context structure
{   
	SSL_METHOD *method;

	SSL_CTX *ctx;       

	OpenSSL_add_all_algorithms();       //Load & register all cryptos and others 

	SSL_load_error_strings();        // Load all error messages 

	method = TLSv1_2_server_method();       // Create new server-method instance 

	ctx = SSL_CTX_new(method);        // Create new context from method 

	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);

		abort();
	}

	return ctx;
}

	
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)   // To load a certificate into an SSL_CTX structure
{
	// Set the local certificate from CertFile 
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);

		abort();
	}

	// Set the private key from KeyFile (may be the same as CertFile) 
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);

		abort();
	}

	// Verify the private key 
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		fprintf(stderr, "Private key does not match the public certificate\n");

		abort();
	}
}

void ShowCerts(SSL* ssl)     //Show the ceritficates to client and match them
{   
	X509 *cert;

	char *line;

	cert = SSL_get_peer_certificate(ssl); // Get certificates (if available) 

	if ( cert != NULL )
	{
		printf("Server certificates:\n");

		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);  

		printf("Server: %s\n", line);     //Server certifcates

		free(line);

		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

		printf("Client: %s\n", line);     //Client certificates

		free(line);

		X509_free(cert);
	}

	else
		printf("\nNo certificates.");
}

void Servlet(SSL* ssl) // Serve the connection -- threadable 
{
	char buf[1024];

	int sd, bytes;

	char input[BUFFER];  

	pid_t cpid; 

	if ( SSL_accept(ssl) == FAIL )     // Do SSL-protocol accept 
		ERR_print_errors_fp(stderr);

	else
	{ 
		ShowCerts(ssl);        // Get any certificates 

		//Fork system call is used to create a new process

		cpid=fork();

		if(cpid==0)
		{ 

			while(1)
			{
				bytes = SSL_read(ssl, buf, sizeof(buf));   // Get request and read message from server

				if ( bytes > 0 )
				{ 
					buf[bytes] = 0;

					printf("\nMESSAGE FROM CLIENT:%s\n", buf);
				}  

				else
					ERR_print_errors_fp(stderr);
			} 
		}

		else 
		{

			while(1)
			{
				printf("\nMESSAGE TO CLIENT:");

				fgets(input, BUFFER, stdin);    // Get request and reply to client

				SSL_write(ssl, input, strlen(input)); 
			}
		}  
	}

	sd = SSL_get_fd(ssl);       // Get socket connection

	SSL_free(ssl);         // Release SSL state

	close(sd);          // Close connection 

}

	
int main(int count, char *strings[])   // Getting port as a argument
{   
	SSL_CTX *ctx;

	int server;

	char *portnum;

	if(!isRoot())      // If root user is not executing server report must be root user 
	{
		printf("This program must be run as root/sudo user!!");

		exit(0);
	}

	if ( count != 2 )
	{
		printf("Usage: %s \n", strings[0]);   // Send the usage guide if syntax of setting port is different

		exit(0);
	}

	SSL_library_init();     // Load encryption and hash algo's in ssl

	portnum = strings[1];

	ctx = InitServerCTX();        // Initialize SSL

	LoadCertificates(ctx, "mycert.pem", "mycert.pem"); // Load certs 

	server = OpenListener(atoi(portnum));    // Create server socket 

	struct sockaddr_in addr;      //Socket for server

	socklen_t len = sizeof(addr);

	SSL *ssl;

	listen(server,5);      // Setting 5 clients at a time to queue

	int client = accept(server, (struct sockaddr*)&addr, &len);  // Accept connection as usual 

	printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));  // Printing connected client information

	ssl = SSL_new(ctx);              // Get new SSL state with context

	SSL_set_fd(ssl, client);      // Set connection socket to SSL state 

	Servlet(ssl);         // Service connection 

	close(server);          // Close server socket 

	SSL_CTX_free(ctx);         // Release context 
}