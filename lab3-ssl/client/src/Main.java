import java.net.InetAddress;
import java.net.UnknownHostException;

public class Main {

    public static void main(String[] args) {
        try {
            InetAddress host = InetAddress.getLocalHost();
            SecureClient c = new SecureClient(host);
            c.setup();
            c.add("1.2 3.4 5.6");
            c.add("5.2 3.4 5.6");
            c.delete("filenameDelete");
            c.download("filenameDownload");
            c.upload("text.txt");
            c.terminate();
        } catch (UnknownHostException uhe) {
            System.out.println(uhe);
            uhe.printStackTrace();
        }
    }
}
