/* Wildcard imports, because too many */
import java.io.*;
import java.nio.file.*;
import javax.net.*;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.*;

/**
 * MyTLSFileServer class.
 *
 * Starts a TLSFileServer session with certificate authentication, using Java's
 * SSL sockets for secure communication and file transfer to MyTLSFileClient.
 *
 * The server-side user will be prompted to enter the server password for the
 * server, which will be passed to {@link #getSSF(char[] password)} to check
 * if correct, then configure the ServerSocketFactor if valid.
 *
 * This program is run on the main Thread, but also contains an anonymous Thread
 * {@link #quitThread} that listens for the signal to commence shutdown, which
 * is given by the user's {@link Console} input.
 *
 * Once a secure connection is established, MyTLSFileServer will check if the
 * requested file exists, then send to MyTLSFileClient in sized-blocks set by
 * default value of {@link #BUFFER}.
 * 
 * Note:    In this version, a 'line' is sent to the client before sending the
 *          file, as a sort of ACK to signal it exists.
 *          
 *          These lines of code can be commented out to remove this function:
 *          160 and 177.
 *
 * @see     MyTLSFileClient     The class that defines client-side this program.
 * @see     SSLSocket           The Socket used to communicate with the client.
 * @see     SSLServerSocket     The server-side Socket that accepts the client.
 */
public class MyTLSFileServer {

    private static final String[] PROTOCOLS = {"TLSv1.2", "TLSv1.3"};
    private static final int PORT = 50202;
    private static final int BUFFER = 1024;

    /**
     * Entry point main.
     *
     * Starts MyTLSFileServer program on the main Thread. By default, the server
     * will listen on {@link PORT}, unless another arg specifies a port number.
     *
     * @param   args    The String array of command-line arguments.
     */
    public static void main(String[] args) {

        /* The SSL resources used for this session */
        SSLServerSocket serverSocket = null;
        ServerSocketFactory socketFactory = null;

        try {
            /* Changes the port if another arg is specified */
            int port = PORT;
            if (args.length == 2) {
                port = Integer.parseInt(args[1]);
            }

            System.out.println("Welcome to MyTLSFileServer!");

            /* ############################################################# */
            /* STEP 3: TLS handshake in the Server */

            /* Sets up Console with a prompt to begin */
            Console console = System.console();
            System.out.print("Enter password: ");

            /* Confirms password and initialises Socket */
            socketFactory = getSSF(console.readPassword());
            serverSocket = (SSLServerSocket)socketFactory.createServerSocket(port);
            serverSocket.setEnabledProtocols(PROTOCOLS);

            System.out.println("Access granted!");

            /* ############################################################# */
            /* Secret step, please ignore */
            /**
             * Anonymous Thread will listen for 'q' to shutdown.
             *
             * This was done for easier testing (server-side) via console.
             * It means that 'q' can be entered at any time and the Socket
             * will be closed immediately, without the need for a 'flag'.
             */
            Thread quitThread = new Thread(new Runnable() {

                private SSLServerSocket serverSocket;

                /**
                 * Runnable 'constructor' method.
                 * ***I feel like this is bad practice?
                 */
                public Runnable init(SSLServerSocket serverSocket) {
                    this.serverSocket = serverSocket;
                    return this;
                }

                /**
                 * Inifinitely loops until 'q' is read from Console.
                 * Then calls method to closeServer with SSLServerSocket.
                 */
                @Override
                public void run() {
                    while (true) {
                        if (console.readLine().equalsIgnoreCase("q")) {
                            closeServer(serverSocket);
                            break;
                        }
                    }
                }
            }.init(serverSocket));
            quitThread.start();

            /* ############################################################# */
            /* STEP 3 (cont.): Listenining for Incoming Connections */
            /*
             * This inifinite loop executes the main part of this program.
             *
             * The server will stay open until interrupted by an error, or if
             * the user enters 'q' to trigger shutdown.
             */
            while (true) {
                System.out.println("\nListening on port " + port + "...");
                System.out.println("***Enter 'q' to quit***");

                /* Accepts a client and sets up IO streams for transfer */
                try (
                    SSLSocket socket = (SSLSocket)serverSocket.accept();
                    BufferedReader in =
                        new BufferedReader(
                            new InputStreamReader(socket.getInputStream()));
                    PrintWriter out =
                        new PrintWriter(socket.getOutputStream(), true);
                ) {
                    String filename = in.readLine(); /* The requested file */

                    System.out.println("\n\tNew client has connected!");
                    System.out.println("\tFile requested: " + filename);
                    System.out.println("\nStarting file transfer...\n");

                    Path path = Paths.get(filename); /* Gets the file path */

                    /* ###################################################### */
                    /* STEP 5: Transfer a file */

                    /*
                     * The following block of code executes the file transfer.
                     *
                     * 1.   If the File exists at the specified Path, then sends
                     *      to the client, via a buffer, through the Socket.
                     *
                     * 2.   If the File doesn't exist, then throws IOException
                     *      to signal File Not Found.
                     */
                    if (Files.exists(path)) {
                        out.println("200 OK"); /* COMMENT OUT THIS LINE */

                        try (
                            InputStream fis = Files.newInputStream(path);
                             BufferedOutputStream bos =
                                new BufferedOutputStream(socket.getOutputStream());
                        ) {
                            byte[] buf = new byte[BUFFER];
                            int toSend;
                            while ((toSend = fis.read(buf)) != -1) {
                                bos.write(buf, 0, toSend);
                                System.out.print(toSend + " bytes sent...\r");
                            }
                            bos.flush(); /* Flush the remaining bytes */
                            System.out.println("\nFile transfer complete!");
                        }                      
                    } else {
                        out.println("404 File Not Found"); /* COMMENT OUT THIS LINE */
                        System.out.println("File didn't exist on the server.");
                    }
                } catch (IOException e) {
                    System.out.println("Ending connection: " + e.getMessage());
                    break;
                }
            }
        } catch (Exception e) {
            System.out.println("Fatal: " + e.getMessage());
        } finally {
            closeServer(serverSocket);
            System.out.println("MyTLSFileServer has closed...");
            System.exit(0);
        }
    }

    /**
     * Initialises a KeyManagerFactory with the server's KeyStore and the
     * server's password.
     *
     * @param   password        Array containing chars of the server password.
     * @return                  The ServerSocketFactory instance of this context.
     * @throws  IOException     When any other Exception is caught.
     */
    private static ServerSocketFactory getSSF(char[] password) throws IOException {

        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            KeyManagerFactory keyFactory = KeyManagerFactory.getInstance("SunX509");
            SSLContext sslContext = SSLContext.getInstance("TLS");

            keyStore.load(new FileInputStream("server.jks"), password);
            keyFactory.init(keyStore, password);
            sslContext.init(keyFactory.getKeyManagers(), null, null);

            return sslContext.getServerSocketFactory();

        } catch (Exception e) {
            /* To deal with the myraid of exceptions this method throws */
            throw new IOException("SSLServerSocketFactory: " + e.getMessage());
        }
    }

    /**
     * Closes the specified SSLServerSocket.
     *
     * @param   socket      The SSLServerSocket to try and close.
     */
    private static void closeServer(SSLServerSocket socket) {

        try {
            socket.close();
        } catch(IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
