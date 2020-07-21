import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.Iterator;
import java.util.Scanner;

public class User {
    private String username;
    private String password;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String filePath;
    private String recipient;

    private X509Certificate cert;

    public static void addUsers() throws IOException, NoSuchAlgorithmException {

        byte[] salt;

        BufferedWriter writer = new BufferedWriter(new FileWriter("Users" + File.separator + "users.bin"));
        String username1 = "dejan";
        salt = Crypto.getSalt();
        String s = salt.toString();
        String password1 = Crypto.sha_256("dejan");
        writer.write(username1 + ":" + s + ":" + password1 + "\n");
        String username2 = "slavko";
        salt = Crypto.getSalt();
        s = salt.toString();
        String password2 = Crypto.sha_256("slavko");
        writer.write(username2 + ":" + s + ":" + password2 + "\n");
        String username3 = "buraz";
        salt = Crypto.getSalt();
        s = salt.toString();
        String password3 = Crypto.sha_256("buraz");
        writer.write(username3 + ":" + s + ":" + password3 + "\n");
        String username4 = "pero";
        salt = Crypto.getSalt();
        s = salt.toString();
        String password4 = Crypto.sha_256("pero");
        writer.write(username4 + ":" + s + ":" + password4 + "\n");
        String username5 = "slavisa";
        salt = Crypto.getSalt();
        s = salt.toString();
        String password5 = Crypto.sha_256("slavisa");
        writer.write(username5 + ":" + s + ":" + password5 + "\n");
        String username6 = "povucen";
        salt = Crypto.getSalt();
        s = salt.toString();
        String password6 = Crypto.sha_256("povucen");
        writer.write(username6 + ":" + s + ":" + password6 + "\n");

        writer.close();

    }

    public boolean login() {
        System.out.println("Username: ");
        Scanner scanner = new Scanner(System.in);
        username = scanner.next();
        System.out.println("Password: ");
        password = scanner.next();
        try {
            BufferedReader reader = new BufferedReader(new FileReader("Users" + File.separator + "users.bin"));
            String line = reader.readLine();


            while (line != null) {
                String credentials[] = line.split(":");

                if (credentials[0].equals(username) && credentials[2].equals(Crypto.sha_256(password))) {
                    return true;
                }
                line = reader.readLine();

            }
        } catch (FileNotFoundException e) {
           System.out.println("Fajl nije pronedjen");
        } catch (IOException e) {
            System.out.println("IO Exception login");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Ne postoji takav algoritam");
        }

        return false;
    }

    public void messageEncrypt() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Unesi putanju do fajla:");
        filePath = scanner.nextLine();
        System.out.println("Unesi korisnika kome zelite da posaljete fajl");
        recipient = scanner.next();

    }

    public void messageDecrypt() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Unesi putanju do fajla:");
        filePath = scanner.nextLine();
      //  System.out.println("Unesi korisnika koji je poslao fajl");
     //   recipient = scanner.next();

    }

    public String getUsername() {
        return username;
    }

    public String getRecipient() {
        return recipient;
    }

    public String getFilePath() {
        return filePath;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public boolean validateCertificate() throws CertificateException, FileNotFoundException, CRLException {
        System.out.println("Unesite putanju do certifikata");
        String path;
        Scanner scanner = new Scanner(System.in);
        path = scanner.nextLine();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream in = new FileInputStream(path);
        cert = (X509Certificate) cf.generateCertificate(in);

        cert.checkValidity(); // validnost datuma u momentu pokretanja

        CertificateFactory cfroot = CertificateFactory.getInstance("X.509");
        FileInputStream inroot = new FileInputStream("CA root" + File.separator + "certs" + File.separator + "ca.crt");
        X509Certificate rootCert = (X509Certificate) cfroot.generateCertificate(inroot);


        FileInputStream fis = new FileInputStream("CA root"+File.separator+"clr"+File.separator+"list.pem");
        X509CRL crl = (X509CRL) cf.generateCRL(fis);
        Iterator<? extends X509CRLEntry> iterator = null;

        if (crl.getRevokedCertificates() != null)
            iterator = crl.getRevokedCertificates().iterator();
        if (iterator != null)
            while (iterator.hasNext()) {
                X509CRLEntry c = iterator.next();
                if (c.getSerialNumber().equals(cert.getSerialNumber())) {
                    System.out.println("Sertifikat korisnika " + username + " je povucen!");
                    return false;
                }
            }
        if (cert.getIssuerDN().getName().equals(rootCert.getIssuerDN().getName()) && cert.getSubjectDN().getName().split(",")[0].split("=")[1].equals(username)) {
            publicKey = cert.getPublicKey();
            return true;
        }
        return false;
    }
}
