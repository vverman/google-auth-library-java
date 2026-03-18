import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class TestPkcs1 {
    public static void main(String[] args) throws Exception {
        String[] lines = new String(Files.readAllBytes(Paths.get("/Users/pjiyer/Documents/google-auth-adc/x509/x509_certs/leaf2048.key"))).split("\n");
        StringBuilder sb = new StringBuilder();
        boolean inKey = false;
        for (String line : lines) {
            if (line.contains("BEGIN RSA PRIVATE KEY")) {
                inKey = true;
                continue;
            }
            if (line.contains("END RSA PRIVATE KEY")) {
                break;
            }
            if (inKey) {
                sb.append(line.trim());
            }
        }
        
        byte[] pkcs1Bytes = Base64.getDecoder().decode(sb.toString());

        int pkcs1Length = pkcs1Bytes.length;
        int totalLength = pkcs1Length + 22;
        byte[] pkcs8Header = new byte[]{
            0x30, (byte) 0x82, (byte) ((totalLength >> 8) & 0xff), (byte) (totalLength & 0xff), // Sequence + length
            0x02, 0x01, 0x00, // Integer: 0
            0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, // Algorithm identifier: rsaEncryption
            0x04, (byte) 0x82, (byte) ((pkcs1Length >> 8) & 0xff), (byte) (pkcs1Length & 0xff) // Octet string + length
        };
        byte[] pkcs8Bytes = new byte[pkcs8Header.length + pkcs1Bytes.length];
        System.arraycopy(pkcs8Header, 0, pkcs8Bytes, 0, pkcs8Header.length);
        System.arraycopy(pkcs1Bytes, 0, pkcs8Bytes, pkcs8Header.length, pkcs1Length);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
        System.out.println("Success!");
    }
}