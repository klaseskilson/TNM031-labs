import javax.net.ssl.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.StringTokenizer;

public class SecureServer {
    private int port;

    static final int DEFAULT_PORT = 8189;
    static final String LABKEYSTORE = "./assets/LABkeystore.ks";
    static final String LABTRUSTSTORE = "./assets/LABtruststore.ks";
    static final String LABSTOREPASSWD = "somekey";
    static final String LABALIASPASSWD = "somekey";
    static final String TERMINATE_CONNECTION = "";
    static final String DELETE_COMMAND = "cmd:delete";
    static final String UPLOAD_COMMAND = "cmd:upload";
    static final String DOWNLOAD_COMMAND = "cmd:download";
    static final String END_COMMAND = "cmd:end";
    static final String FOLDER = "files/";

    BufferedReader inputStream;
    PrintWriter outputStream;

    /**
     * default constructor
     */
    SecureServer () {
        this.port = DEFAULT_PORT;
    }

    /**
     * constructor
     * @param port the port number
     */
    SecureServer (int port) {
        this.port = port;
    }

    public void run() {
        try {
            // load keystores
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(new FileInputStream(LABKEYSTORE),
                    LABSTOREPASSWD.toCharArray());
            KeyStore ts = KeyStore.getInstance("JCEKS");
            ts.load(new FileInputStream(LABTRUSTSTORE),
                    LABSTOREPASSWD.toCharArray());

            // setup key/trust managers
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, LABALIASPASSWD.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);

            // setup ssl server
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(),
                            tmf.getTrustManagers(),
                            null);
            SSLServerSocketFactory sslServer = sslContext.getServerSocketFactory();

            SSLServerSocket sss = (SSLServerSocket) sslServer.createServerSocket(this.port);
            sss.setEnabledCipherSuites(sss.getSupportedCipherSuites());

            sss.setNeedClientAuth(true);

            System.out.println("SecureServer running on port " + this.port);

            // prepare incoming connections
            SSLSocket incoming = (SSLSocket) sss.accept();
            inputStream = new BufferedReader(
                    new InputStreamReader(incoming.getInputStream()));
            outputStream = new PrintWriter(incoming.getOutputStream(), true);
            String str;

            // handle incoming transmissions
            while (!(str = inputStream.readLine()).equals(TERMINATE_CONNECTION)) {
                System.out.println(str);
                switch (str) {
                    case UPLOAD_COMMAND:
                        receiveFromClient();
                        break;
                    case DOWNLOAD_COMMAND:
                        sendToClient();
                        break;
                    case DELETE_COMMAND:
                        delete();
                        break;
                    default:
                        break;
                }
            }
            // close connection
            incoming.close();
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }

    private void delete() {
        try {
            String str;
            String fileName = null;
            while (!(str = inputStream.readLine()).equals(END_COMMAND)) {
                fileName = str;
            }

            if (fileName != null) {
                try {
                    File file = new File(FOLDER + fileName);
                    if (file.delete()) {
                        outputStream.println("deleted " + fileName);
                    }
                } catch (Exception e) {
                    outputStream.println("not deleted");
                }
            }

        } catch (Exception e) {
            outputStream.println("Something went wrong");
            System.out.println(e);
            e.printStackTrace();
        }
    }

    private void sendToClient() {
        System.out.println("Sending to client");
        try {
            String str;
            String fileName = null;
            while (!(str = inputStream.readLine()).equals(END_COMMAND)) {
                // receive filename
                fileName = str;
                System.out.println("filename: " + fileName);
            }

            if (fileName != null) {
                // read file and send it
                try (BufferedReader reader = new BufferedReader(
                        new FileReader(FOLDER + fileName))) {
                    // read file and send it to client
                    String line;
                    while ((line = reader.readLine()) != null) {
                        outputStream.println(line);
                    }
                } catch (IOException ioe) {
                    outputStream.println("File does not exist!");
                    System.out.println(ioe);
                    ioe.printStackTrace();
                }
            }
            System.out.println("ending, file sent");

            // notify client end of file transmission
            outputStream.println(END_COMMAND);
        } catch (Exception e) {
            outputStream.println("Something went wrong");
            System.out.println(e);
            e.printStackTrace();
        }
    }

    private void receiveFromClient() {
        try {
            StringBuilder fileContent = new StringBuilder();
            String fileName = null;
            String str;
            while (!(str = inputStream.readLine()).equals(END_COMMAND)) {
                // use first line as file name
                if (fileName == null) {
                    fileName = str;
                } else {
                    fileContent.append(str + "\n");
                }
            }

            System.out.println("filename: " + fileName);

            // write to file
            String file = fileContent.toString();
            try (BufferedWriter writer = new BufferedWriter(
                    new FileWriter(FOLDER + fileName))) {
                writer.write(file, 0, file.length());
            } catch (IOException x) {
                System.err.format("IOException: %s%n", x);
            }
            System.out.println("DONE client -> server");
        } catch (Exception e) {
            outputStream.println("Something went wrong");
            System.out.println(e);
            e.printStackTrace();
        }
    }
}
