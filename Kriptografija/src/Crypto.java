import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Iterator;
import java.util.Scanner;

import static java.util.Base64.getDecoder;

public class Crypto {

    public static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    public static String sha_256(String string) throws NoSuchAlgorithmException {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] hashbytes = digest.digest(
            string.getBytes(StandardCharsets.UTF_8));
        String hash = Base64.getEncoder().encodeToString(hashbytes);
        return hash;
    }


    public static byte[] encrypt(byte[] bajtFajl, SecretKey key) throws OutOfMemoryError {
        byte[] result = null;
        try {
            Cipher cipher = Cipher.getInstance(key.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, key);
            result = cipher.doFinal(bajtFajl);
        } catch (OutOfMemoryError ex) {
            throw ex;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return result;
    }

    public static byte[] decrypt(byte[] bajtFajl, SecretKey key) throws BadPaddingException {
        byte[] result = null;
        try {
            Cipher cipher = Cipher.getInstance(key.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, key);
            result = cipher.doFinal(bajtFajl);

        } catch (BadPaddingException bpe) {
            throw bpe;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return result;
    }

    public static PrivateKey getPrivateKey(String user) {
        File f = new File("Users" + File.separator + user + File.separator + "private" + File.separator + user + ".pem");
        try {
            BufferedReader reader = new BufferedReader(new FileReader("Users" + File.separator + user + File.separator + "private" + File.separator + user + ".pem"));
            String privateKey = "";
            String line = "";
            while ((line = reader.readLine()) != null) {
                privateKey += line;
            }
            privateKey = privateKey.replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "");
            byte[] privateKeyByteArray = getDecoder().decode(privateKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            KeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);
            PrivateKey key = kf.generatePrivate(keySpec);
            return key;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] encryptKey(byte[] keyBytes, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = null;

            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(keyBytes);

    }

    public static byte[] decryptKey(byte[] keyBytes, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = null;

            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(keyBytes);


    }

    public static void encryptFileWithDES(String path, PublicKey publicKey, User user) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        File f = new File(path);

        FileInputStream fis = new FileInputStream(f);
        byte[] fajl = new byte[fis.available()];
        fis.read(fajl);
        System.out.println("Unesite algoritam za kriptovanje 1:AES 2:DES 3:DESede(default)");
        String algoritam;
        Scanner in = new Scanner(System.in);
        algoritam = in.nextLine();
        if(algoritam.equals("1"))
            algoritam="AES";
        else if(algoritam.equals("2"))
            algoritam="DES";
        else algoritam="DESede";
        System.out.println("Unesite algoritam za hesiranje 1:SHA256WithRSA ili 2:SHA512WithRSA(default)");
        String hash;
        Scanner inn = new Scanner(System.in);
        hash = inn.nextLine();
        if (hash.equals("1"))
            hash = "SHA256WithRSA";
        else
            hash = "SHA512WithRSA";


        String s ="Filename\n" + f.getName() + "\nPosiljalac" + "\n" + user.getUsername() + "\n" + "Primalac\n" + user.getRecipient() + "\n" + "Algoritam\n" + algoritam + "\nHash\n" + hash + "\nFile\n";

        SecretKey randomKey = KeyGenerator.getInstance(algoritam).generateKey();
        byte[] fa = Crypto.encrypt(fajl, randomKey);
        s += Base64.getEncoder().encodeToString(fa) + "\n" + "Key";

        BufferedWriter writer = new BufferedWriter(new FileWriter("Users" + File.separator + user.getRecipient() + File.separator + "box" + File.separator + f.getName()));

        byte[] pom = Crypto.encryptKey(randomKey.getEncoded(), publicKey);

        s += "\n" + (Base64.getEncoder().encodeToString(pom)) + "\n";


        Signature signature = Signature.getInstance(hash);
        SecureRandom secureRandom = new SecureRandom();
        signature.initSign(Crypto.getPrivateKey(user.getUsername()), secureRandom);
        byte[] temp = s.getBytes("UTF-8");


        s += "Signiture\n";
        signature.update(temp);
        byte[] digitalSignature = signature.sign();
        String temp1 = Base64.getEncoder().encodeToString(digitalSignature);

        writer.write(s + temp1);
        writer.close();

    }

    public static String decryptFileWithDES(String path, PrivateKey privateKey, User user) throws IOException, BadPaddingException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, SignatureException, IllegalBlockSizeException, NoSuchPaddingException, CRLException {
        BufferedReader reader = new BufferedReader(new FileReader(path));
        String s = "";

        String filename = reader.readLine();
        s += filename + "\n";
        filename = reader.readLine();
        s += filename + "\n";
        String username = reader.readLine();
        s += username + "\n";
        username = reader.readLine();
        s += username + "\n";
        String recipient = reader.readLine();
        s += recipient + "\n";
        recipient = reader.readLine();
        s += recipient + "\n";
        String algorithm = reader.readLine();
        s += algorithm + "\n";
        algorithm = reader.readLine();
        s += algorithm + "\n";
        String hash = reader.readLine();
        s += hash + "\n";
        hash = reader.readLine();
        s += hash + "\n";
        String file = reader.readLine();
        s += file + "\n";
        file = reader.readLine();
        s += file + "\n";
        String key = reader.readLine();
        s += key + "\n";
        key = reader.readLine();
        s += key + "\n";
        String sign = reader.readLine();
        sign = reader.readLine();


        Signature signature = Signature.getInstance(hash);
        FileInputStream in = new FileInputStream("Users" + File.separator + username + File.separator + "certs" + File.separator + username + ".crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
        PublicKey publicKey = cert.getPublicKey();
        signature.initVerify(publicKey);
        Crypto.verifyCertificate(cert);
        byte[] data2 = s.getBytes("UTF-8");
        signature.update(data2);
        boolean verified = signature.verify(Base64.getDecoder().decode(sign));
        if (verified) {

            byte[] keyBytes = Base64.getDecoder().decode(key);
            byte[] keyBytesDecrypt = Crypto.decryptKey(keyBytes, privateKey);
            SecretKey secretKey = new SecretKeySpec(keyBytesDecrypt, 0, keyBytesDecrypt.length, algorithm);
            byte[] fileBytes = Base64.getDecoder().decode(file);
            byte[] file1 = Crypto.decrypt(fileBytes, secretKey);
            String pathString = "Users" + File.separator + user.getUsername() + File.separator + "box" + File.separator + filename;
            Path path1 = Paths.get(pathString);
            Files.write(path1, file1);
            return pathString;
        } else throw new SignatureException();
    }
    public static void verifyCertificate(X509Certificate certificate) throws CertificateException, FileNotFoundException, CRLException {
        certificate.checkValidity(); // validnost datuma u momentu pokretanja

        CertificateFactory cfroot = CertificateFactory.getInstance("X.509");
        FileInputStream inroot = new FileInputStream("CA root" + File.separator + "certs" + File.separator + "ca.crt");
        X509Certificate rootCert = (X509Certificate) cfroot.generateCertificate(inroot);


        FileInputStream fis = new FileInputStream("CA root"+File.separator+"clr"+File.separator+"list.pem");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL) cf.generateCRL(fis);
        Iterator<? extends X509CRLEntry> iterator = null;

        if (crl.getRevokedCertificates() != null)
            iterator = crl.getRevokedCertificates().iterator();
        if (iterator != null)
            while (iterator.hasNext()) {
                X509CRLEntry c = iterator.next();
                if (c.getSerialNumber().equals(certificate.getSerialNumber())) {

                    throw  new CertificateException("");
                }
            }
        if (certificate.getIssuerDN().getName().equals(rootCert.getIssuerDN().getName()) ) {

            return;
        }
       throw  new CertificateException("");

    }


}
