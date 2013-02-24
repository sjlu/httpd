#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gcrypt.h>

/*
 * Tell us where you put the certificates
 * Only KEYFILE and CERTFILE are required.
 */
#define KEYFILE "certs/server.key"
#define CERTFILE "certs/server.crt"
#define CAFILE "certs/ca.pem"
#define CRLFILE "certs/crl.pem"

/*
 * Setting some variables
 */
#define SA struct sockaddr
#define SOCKET_ERR(err,s) if(err==-1) {perror(s);return(1);}
#define MAX_BUF 2048
#define DH_BITS 1024

/*
 * Setting default port
 */
#define PORT 8443

/*
 * Setting global variables, specifically
 * the server generated certificate creds
 */
gnutls_certificate_credentials_t x509_cred;
gnutls_psk_server_credentials_t psk_cred;
gnutls_priority_t priority_cache;

/*
 * Starts a standard gnutls session
 * on a server port.
 */
static gnutls_session_t initialize_tls_session (void)
{
   gnutls_session_t session;

   gnutls_init (&session, GNUTLS_SERVER);

   gnutls_priority_set (session, priority_cache);

   gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
   gnutls_credentials_set (session, GNUTLS_CRD_PSK, psk_cred);

   gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);

   return session;
}

static gnutls_dh_params_t dh_params;

static int generate_dh_params (void)
{
   gnutls_dh_params_init (&dh_params);
   gnutls_dh_params_generate2 (dh_params, DH_BITS);

   return 0;
}

static int pskfunc (gnutls_session_t session, const char *username, gnutls_datum_t * key)
{
   key->data = gnutls_malloc (4);
   key->data[0] = 0xDE;
   key->data[1] = 0xAD;
   key->data[2] = 0xBE;
   key->data[3] = 0xEF;
   key->size = 4;
   return 0;
}

void err_exit()
{
   perror("web-server");
   exit(1);
}

/*
 * Reads the input client headers, one character at a time
 * at a maximum of one line that is truncated by "\r\n"
 * is when we identify the new line
 */
char* read_line(gnutls_session_t session, char* line, int length) {
   char c = 'a';
   char *line_ptr = line;
   int curr_length = 0;

   while (1)
   {
      if (gnutls_record_recv(session, &c, sizeof(c)) <= 0)
         err_exit();

      if (c == '\n')
         break;

      curr_length++;

      if (curr_length > length)
         break;

      *line_ptr++ = c;
   }

   if ((line_ptr-1) == '\n')
      *(line_ptr-1) = 0;
   else
      *line_ptr = 0;

   return line;
}

/*
 * This translates a file name's extention
 * into a proper MIME type that our server
 * recognizes.
 */
char* get_content_type(char* input, char* line, int length) {
   char *token;
   char *tokenizer;

   token = strtok_r(input, ".", &tokenizer);
   while (token != NULL)
   {
      strcpy(line, token); 
      token = strtok_r(NULL, ".", &tokenizer);
   }

   if (strcmp(line, "html") == 0)
      strcpy(line, "text/html");
   else if (strcmp(line, "js") == 0)
      strcpy(line, "application/javascript");
   else if (strcmp(line, "jpg") == 0)
      strcpy(line, "image/jpeg");
   else if (strcmp(line, "png") == 0)
      strcpy(line, "image/png");
   else if (strcmp(line, "php") == 0)
      strcpy(line, "application/php");
   else
      strcpy(line, "text/text");

   return line;
}

/*
 * Processes the incoming request
 */
void process_request(gnutls_session_t session) 
{
   char buffer[MAX_BUF + 1];
   char header[MAX_BUF];

   /*
    * Reset mem, read the client header into
    * the buffer.
    */
   memset (buffer, 0, MAX_BUF + 1);
   char *buf = read_line(session, buffer, MAX_BUF);

   printf("\t%s\n", buf);

   /*
    * Sepearate our first line request header
    * into separate parts, specifically we need
    * the file path its requesting
    */
   char *token;
   char *tokenizer;

   token = strtok_r(buf, " ", &tokenizer);
   token = strtok_r(NULL, " ", &tokenizer);

   char *file_name = strdup(token); 

   /*
    * If no file is listed, we default to
    * index.html
    */
   if (strcmp(file_name, "/") == 0)
      strcpy(file_name, "/index.html");

   /*
    * Setting where to serve content form
    */
   char path[MAX_BUF];
   snprintf(path, MAX_BUF, "content%s", file_name);

   /*
    * Opening the file, if it doesn't exist we stop here
    * and send a 404 Not found header to the client
    */
   FILE *file = fopen(path, "r");
   if (file == NULL)
   {
      fprintf(stderr, "\tFile not found.\n"); 
      snprintf(header, MAX_BUF, "HTTP/1.1 404 Not Found\r\n\r\n");
      if (gnutls_record_send(session, header, strlen(header)) < 0)
         err_exit();
   }
   else
   {
      /*
       * File found, get the mime type
       */
      char content_buffer[MAX_BUF];
      char *mime = get_content_type(path, content_buffer, MAX_BUF);
      printf("\tContent type detected: %s\n", mime);

      /*
       * If it is PHP, we will close the currentl file descriptor
       * and set it to the execution of the script. The output
       * of the command is now our file descriptor
       */
      if (strcmp(mime, "application/php") == 0)
      {
         printf("\tExecuting PHP file.\n");
         fclose(file);

         snprintf(path, MAX_BUF, "php content%s", file_name);
         file = popen(path, "r");

         if (file == NULL)
            err_exit();

         // change the mime type.
         strcpy(mime, "text/html");
      }

      /*
       * Check to see how big the file is
       */
      fseek(file, 0, SEEK_END);
      int file_size = ftell(file);
      fseek(file, 0, SEEK_SET);

      /*
       * Read the content into here
       */
      char *file_string = malloc(file_size+1);
      fread(file_string, 1, file_size, file);
   
      /*
       * Hotfix, PHP gives us a filesize of -1 apparently,
       * we need to use strlen to actually read the size of
       * the content from PHP
       */
      if (file_size == -1)
         file_size = strlen(file_string);

      printf("\tFile size: %d\n", file_size);

      /*
       * Send the HTTP 200 OK header, the content type
       * and the content length to the browser.
       */
      snprintf(header, MAX_BUF, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n", mime, file_size);
      if (gnutls_record_send(session, header, strlen(header)) < 0)
         err_exit();

      /*
       * Sending the content to the client
       * Needs to be chuncked because of the sending
       * limitations of gnutls.
       */
      int bytes_read = 0;
      int bytes_sending;
      char *str_ptr = file_string;

      while (bytes_read < file_size)
      {  
         if ((file_size - bytes_read) < MAX_BUF) 
            bytes_sending = file_size - bytes_read;
         else
            bytes_sending = MAX_BUF;

         //printf("\tSent: %d bytes\n", bytes_sending);

         if (gnutls_record_send(session, str_ptr, bytes_sending) < 0)
            err_exit();

         str_ptr += bytes_sending;
         bytes_read += bytes_sending;
      }
   }
}

int main (void)
{
   /*
    * Variable init
    */
   int err, listen_sd;
   int sd, ret;
   struct sockaddr_in sa_serv;
   struct sockaddr_in sa_cli;
   int client_len;
   char topbuf[512];
   gnutls_session_t session;
   int optval = 1;

   /*
    * SSL TLS utility init
    * This will add the certificate files properly
    * to the TLS session we are about to create.
    */
   gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

   gnutls_global_init ();

   gnutls_certificate_allocate_credentials (&x509_cred);
   gnutls_certificate_set_x509_trust_file (x509_cred, CAFILE, GNUTLS_X509_FMT_PEM);

   gnutls_certificate_set_x509_crl_file (x509_cred, CRLFILE, GNUTLS_X509_FMT_PEM);

   gnutls_certificate_set_x509_key_file (x509_cred, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM);

   gnutls_psk_allocate_server_credentials (&psk_cred);
   gnutls_psk_set_server_credentials_function (psk_cred, pskfunc);

   generate_dh_params ();

   gnutls_priority_init (&priority_cache, "NORMAL:PSK", NULL);

   gnutls_certificate_set_dh_params (x509_cred, dh_params);

   /*
    * Web server socket stuff
    */
   listen_sd = socket (AF_INET, SOCK_STREAM, 0);
   SOCKET_ERR (listen_sd, "socket");

   memset (&sa_serv, '\0', sizeof (sa_serv));
   sa_serv.sin_family = AF_INET;
   sa_serv.sin_addr.s_addr = INADDR_ANY;
   sa_serv.sin_port = htons (PORT);	/* Server Port number */

   setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof (int));

   err = bind (listen_sd, (SA *) & sa_serv, sizeof (sa_serv));
   SOCKET_ERR (err, "bind");
   err = listen (listen_sd, 1024);
   SOCKET_ERR (err, "listen");

   /*
    * Listening for clients this will SSLize
    * the incoming connection by properly doing the "handshake"
    */
   client_len = sizeof (sa_cli);
   for (;;)
   {
      session = initialize_tls_session ();

      sd = accept(listen_sd, (SA *) & sa_cli, &client_len);
      pid_t pid = fork();
      if (pid == 0) 
         break; 
      else 
         continue;
   }

   printf ("Connection received from %s:%d\n", 
      inet_ntop (AF_INET, &sa_cli.sin_addr, topbuf, sizeof (topbuf)), 
      ntohs (sa_cli.sin_port));

   gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);

   ret = gnutls_handshake (session);
   if (ret < 0)
   {
      close (sd);
      gnutls_deinit (session);
      fprintf (stderr, "\tSSL handshake failed!\n\tError: %s\n\n", gnutls_strerror(ret));
   }
   printf ("\tSSL handshake successful!\n");

   /*
    * Send it for processing
    */
   process_request(session);

   printf ("\n");

   /*
   * Closing connection.
   */
   gnutls_bye (session, GNUTLS_SHUT_WR);

//      close (sd);
   gnutls_deinit (session);

   /*
    * Properly closing the TLS connection
    * we created to the web server.
    */
   close (listen_sd);

   gnutls_certificate_free_credentials (x509_cred);
   gnutls_psk_free_server_credentials (psk_cred);

   gnutls_priority_deinit (priority_cache);

   gnutls_global_deinit ();

   return 0;
}
