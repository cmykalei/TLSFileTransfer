import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.*;
import java.net.UnknownHostException;
import javax.naming.InvalidNameException;

/**
 * MyTLSFileClient class.
 *
 * Defines the client-side operations of a TLS Handshake and file transfer.
 *
 * Note:    In this version, a 'line' is sent by the server before sending the
 *          file, as a sort of ACK to signal it exists. The reason for this is
 *          so that a dummy file wont be made if it doesn't exist.
 *
 *          These lines of code can be commented out to remove this function:
 *          113 to 117.
 *
 * @see     MyTLSFileServer
 */
public class MyTLSFileClient {

    private static final int BUFFER = 1024; /* Should match the server-side */

    /**
     * Entry point main.
     *
     * Starts MyTLSFileClient with the specified args to request a file.
     * Performs host validation and SSL Handshake to verify a secure connection.
     *
     * @param   args    The String array of command-line arguments.
     */
    public static void main(String[] args) {

        /*
         * The SSL resources used for this session.
         * This was mainly done to shorten the line-length to 80 characters...
         */
        SSLSocket socket = null;
        SSLParameters params = null;
        SSLSocketFactory socketFactory = null;
        SSLSession session = null;
        X509Certificate cert = null;

        if (args.length != 3) {
            System.out.println("Usage: java MyTLSFileClient <hostname> <port> <filename>");
            System.exit(0);
        } else {

            /*
             * This try-catch block sets up a secure connection to the server.
             * It contains a nested 'try-with' block that executes download.
             */
            try {
                String hostname = args[0];             /* The server hostname */
                int port = Integer.parseInt(args[1]);  /* The port to connect */
                String filename = args[2];             /* The file to request */

                System.out.println("\nWelcome to MyTLSFileClient!\n");
                System.out.println("\tYou requested: " + filename);
                System.out.println("\nStarting TLS Handshake...\n");

                /* ###################################################### */
                /* STEP 4: TLS Handshake in the Client */

                /* Sets up the SSLSocket with the specified host and port */
                socketFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();
                socket = (SSLSocket)socketFactory.createSocket(hostname, port);

                /* Sets up the SSL params for host verification */
                params = new SSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS");

                /* Set SSL params for the socket and start the TLS Handshake */
                socket.setSSLParameters(params);
                socket.startHandshake();

                /* Get the certificate for this session to verify connection */
                session = socket.getSession();
                cert = (X509Certificate)session.getPeerCertificates()[0];

                /* If no exception was thrown, certifcate was approved */
                System.out.println("\tCertificate approved!");
                System.out.println("\tCN=" + getCommonName(cert));

                /* ###################################################### */
                /* STEP 5: Transfer (receive) a file */

                /*
                 * This try-with block performs the file download.
                 *
                 * 1.   The String filename is sent to MyTLSFileServer over the
                 *      Socket's OutputStream.
                 *
                 * 2.   The file bytes, as the server is fulfilling the request,
                 *      are read from the Socket's BufferedInputStream.
                 *
                 * 3.   The file is downloaded on the FileInputStream, wrapped
                 *      in a BufferedOutputStream, and received in blocks.
                 */
                try (
                    PrintWriter out =
                        new PrintWriter(socket.getOutputStream(), true);
                    BufferedReader in =
                        new BufferedReader(
                            new InputStreamReader(socket.getInputStream()));
                ) {
                    /* Request the file */
                    out.println(filename);

                    /* COMMENT OUT HERE (Extra stuff) */
                    /* Check if exists before creating File stream */
                    if (in.readLine().equals("404 File Not Found")) {
                        throw new IOException("File Not Found.");
                    }
                    /* RESUME HERE */

                    try (
                        BufferedInputStream bis =
                            new BufferedInputStream(socket.getInputStream());
                        FileOutputStream fos =
                            new FileOutputStream("tls_" + filename);
                        BufferedOutputStream bos =
                            new BufferedOutputStream(fos);
                    ) {
                        System.out.println("\nDownloading...\n");
                        System.out.printf("%-15s%-10s%n", "blocks", "bytes");

                        /* Receive in a buffer */
                        byte[] buf = new byte[BUFFER];
                        int bytes = 0;
                        int blocks = 0;

                        /* Write to new file */
                        while ((bytes = bis.read(buf)) != -1) {
                            bos.write(buf, 0, bytes);
                            System.out.printf("\r%-15d%-10d\r", ++blocks, bytes);
                        }
                        bos.flush();
                        System.out.println("\n\nDownload complete!\n");
                    }
                } catch (IOException e) {
                    System.out.println("\nDownload failed: " + e.getMessage());
                }
            } catch (SSLHandshakeException | SSLPeerUnverifiedException e) {
                System.out.println("\nVerification issue: " + e.getMessage());
            } catch (UnknownHostException e) {
                System.out.println("\nUnknownHostException: " + e.getMessage());
            } catch (IOException e) {
                System.out.println("\nIOException: " + e.getMessage());
            } finally {
                closeClient(socket);
                System.out.println("\nMyTLSFileClient has closed...\n");
            }
        }
    }

    /**
     * Gets the CN (Common Name) from the certificate.
     *
     * @param   cert            The X509Certificate for this session.
     * @return                  The CommonName as a String, if it's valid.
     * @throws  IOException     When an InvalidNameException is caught.
     */
    private static String getCommonName(X509Certificate cert) throws IOException {

        try {
            String cn = cert.getSubjectX500Principal().getName();
            LdapName ldn = new LdapName(cn);

            for (Rdn rdn : ldn.getRdns()) {
                if (rdn.getType().equals("CN")) {
                    return rdn.getValue().toString();
                }
            }
            return cn + " could not be verified.";
        } catch (InvalidNameException e) {
            throw new IOException("InvalidNameException: " + e.getMessage());
        }
    }

    /**
     * Closes the specified SSLSocket.
     *
     * @param   socket      The SSLSocket to try and close.
     */
    private static void closeClient(SSLSocket socket) {

        try {
            socket.close();
        } catch(IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
