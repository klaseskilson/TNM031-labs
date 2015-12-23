package SecureElection.Common;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.net.InetAddress;
import java.security.KeyStore;

public class Client {

    private String keystore, truststore, passphrase;
    private int port;
    private InetAddress host;

    SSLSocket socket;

    public Client(String keystore, String truststore, String passphrase, InetAddress host, int port) {
        this.keystore = keystore;
        this.truststore = truststore;
        this.passphrase = passphrase;
        this.host = host;
        this.port = port;
        init();
    }

    private void init() {
        try {
            // load keystores
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(new FileInputStream(keystore),
                    passphrase.toCharArray());
            KeyStore ts = KeyStore.getInstance("JCEKS");
            ts.load(new FileInputStream(truststore),
                    passphrase.toCharArray());

            // setup key managers
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, passphrase.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);

            // setup ssl
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            SSLSocketFactory sslFact = sslContext.getSocketFactory();

            System.out.println("Connecting socket to " + host.toString() + ":" + port);
            socket = (SSLSocket) sslFact.createSocket(host, port);
            socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public SSLSocket getSocket() {
        return socket;
    }
}
