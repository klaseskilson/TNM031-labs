import java.net.InetAddress;
import java.net.UnknownHostException;

public class Main {

    public static void main(String[] args) {
        try {
            InetAddress host = InetAddress.getLocalHost();
            SecureClient c = new SecureClient(host);
            c.setup();
            c.upload("text.txt");
            c.download("download_me.txt");
            c.delete("text.txt");
            c.terminate();
        } catch (UnknownHostException uhe) {
            System.out.println(uhe);
            uhe.printStackTrace();
        }
    }
}
