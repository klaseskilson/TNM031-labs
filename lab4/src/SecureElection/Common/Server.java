package SecureElection.Common;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.security.KeyStore;

public class Server {
    private String keystore, truststore, passphrase;
    private int port;
    private SSLServerSocket sss;

    public Server(String keystore, String truststore, String passphrase, int port) {
        this.keystore = keystore;
        this.truststore = truststore;
        this.passphrase = passphrase;
        this.port = port;
        init();
    }

    public void init() {
        try {
            // load keystores
            System.out.print("loading keystores... ");
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(new FileInputStream(keystore),
                    passphrase.toCharArray());
            KeyStore ts = KeyStore.getInstance("JCEKS");
            ts.load(new FileInputStream(truststore),
                    passphrase.toCharArray());
            System.out.print("done.\n");

            // setup key/trust managers
            System.out.print("Preparing trust managers... ");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, passphrase.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);
            System.out.print("done.\n");

            // setup ssl server
            System.out.print("Starting server... ");
            SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            SSLServerSocketFactory sslServer = serverContext.getServerSocketFactory();
            System.out.print("done.\n");

            sss = (SSLServerSocket) sslServer.createServerSocket(port);
            sss.setEnabledCipherSuites(sss.getSupportedCipherSuites());

            // require socket auth
            sss.setNeedClientAuth(true);
            System.out.println("Server running on port " + port);
        } catch (Exception e) {
            System.out.println("Could not initiate server:");
            e.printStackTrace();
        }
    }

    public SSLServerSocket getServerSocket() {
        return sss;
    }
}
