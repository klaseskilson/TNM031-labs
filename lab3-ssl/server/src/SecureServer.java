import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.util.StringTokenizer;

public class SecureServer {
    private int port;

    static final int DEFAULT_PORT = 8189;
    static final String LABKEYSTORE = "./assets/LABkeystore.ks";
    static final String LABTRUSTSTORE = "./assets/LABtruststore.ks";
    static final String LABSTOREPASSWD = "somekey";
    static final String LABALIASPASSWD = "somekey";
    final static String TERMINATE_CONNECTION = "";
    final static String END_COMMAND = "cmd:end";

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
                    case "cmd:add":
                        add();
                        break;
                    case "cmd:upload":
                        receiveFromClient();
                        break;
                    case "cmd:download":
                        sendToClient();
                        break;
                    case "cmd:delete":
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

    private void add() {

        try {
            String str;
            double result = 0;
            while (!(str = inputStream.readLine()).equals(END_COMMAND)) {
                StringTokenizer st = new StringTokenizer(str);

                try {
                    while (st.hasMoreTokens()) {
                        result += new Double(st.nextToken());
                    }
                    outputStream.println("The result is " + result);
                } catch (NumberFormatException nfe) {
                    outputStream.println("Weird format");
                }
            }
        } catch (Exception e) {
            outputStream.println("Something went wrong");
            System.out.println(e);
            e.printStackTrace();
        }
    }

    private void delete() {
        try {
            String str;
            while (!(str = inputStream.readLine()).equals(END_COMMAND)) {
                outputStream.println("calling delete ");
                System.out.println(str);
            }
        } catch (Exception e) {
            outputStream.println("Something went wrong");
            System.out.println(e);
            e.printStackTrace();
        }
    }

    private void sendToClient() {
        try {
            String str;
            while (!(str = inputStream.readLine()).equals(END_COMMAND)) {
                // recieve filename
                String fileName = str;
                try (BufferedReader reader = new BufferedReader(
                        new FileReader("files/" + fileName))) {
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
                outputStream.println("calling receiveFromClient ");
                System.out.println(str);

                // if dont have a file name
                if (fileName == null) {
                    fileName = str;
                } else {
                    fileContent.append(str + "\n");
                }
            }

            // write to file
            String file = fileContent.toString();
            try (BufferedWriter writer = new BufferedWriter(
                    new FileWriter("files/" + fileName))) {
                writer.write(file, 0, file.length());
            } catch (IOException x) {
                System.err.format("IOException: %s%n", x);
            }
        } catch (Exception e) {
            outputStream.println("Something went wrong");
            System.out.println(e);
            e.printStackTrace();
        }
    }
}
