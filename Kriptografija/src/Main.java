import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.Scanner;


public class Main {

    public static void main(String[] args) {

        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            User.addUsers();
            User user = new User();
            if (user.login() && user.validateCertificate()) {
                String opcija;
                System.out.println("1-Kriptovanje ,2-Dekriptovanje, Kraj programa(default)");
                Scanner scanner = new Scanner(System.in);
                opcija = scanner.next();

                switch (opcija) {
                    case "1":
                        user.messageEncrypt();
                        FileInputStream in = new FileInputStream("Users" + File.separator + user.getRecipient() + File.separator + "certs" + File.separator + user.getRecipient() + ".crt");
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");

                        X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
                        Crypto.verifyCertificate(cert);
                        PublicKey publicKey = cert.getPublicKey();
                        Crypto.encryptFileWithDES(user.getFilePath(), publicKey, user);
                        break;
                    case "2":
                        user.messageDecrypt();
                        String pom = Crypto.decryptFileWithDES(user.getFilePath(), Crypto.getPrivateKey(user.getUsername()), user);

                        System.out.println("Da li zelite da kompajlirate dekriptovanu datoteku: 1-da 2-ne");
                        String string;
                        Scanner da = new Scanner(System.in);
                        string = da.nextLine();
                        if (string.equals("1")) {
                            new Thread() {
                                String pom1 = pom;

                                public void run() {
                                    try {
                                        Runtime rt = Runtime.getRuntime();
                                        JavaCompiler comp = ToolProvider.getSystemJavaCompiler();
                                        comp.run(null, null, null, pom1);
                                        //sleep(2000);
                                        File f = new File(pom);

                                        System.out.println(new String(rt.exec("java " + f.getName().split("\\.")[0], null, new File("Users" + File.separator + user.getUsername() + File.separator + "box"))
                                            .getInputStream().readAllBytes()));
                                    } catch (Exception e) {
                                        System.out.println("Greska prilikom pokretanja! ");
                                    }
                                }
                            }.start();
                        }
                        break;
                }
            } else {
                System.out.println("Unjeli ste pogresne kredencijale ili certifikat nije validan");
            }

        } catch (SignatureException e) {
            System.out.println("potpis nije validan");
        } catch (FileNotFoundException e) {
            System.out.println("Parametri putanja  posiljalac/primalac ne postoje");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Ne postoji takav algoritam");
        } catch (CertificateException e) {
            System.out.println("Neodgovarajuci certifikat");
        } catch (InvalidKeyException e) {
            System.out.println("neodgovarajuci kljuc");
        } catch (IOException e) {
            System.out.println("Neodgovarajuci IO");
        } catch (CRLException e) {
            System.out.println("Problem sa CRL listom");
        } catch (BadPaddingException e) {
            System.out.println("Neodgovarajuci kljuc");
        } catch (NoSuchPaddingException e) {
            System.out.println("exeption");
        } catch (IllegalBlockSizeException e) {
            System.out.println("exeption");
        }
    }
}
