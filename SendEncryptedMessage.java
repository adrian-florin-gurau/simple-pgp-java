package ro.ase.ism.sap.adrian.florin.gurau;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class SendEncryptedMessage {
    public static byte[] generateSecureRandomKey(
            String algorithm, int noBits) throws NoSuchAlgorithmException, NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(noBits);
        return keyGenerator.generateKey().getEncoded();
    }

    public static String toBase64(byte[] value) {
        if (value == null) {
            return null;
        }
        return Base64.getEncoder().encodeToString(value);
    }

    public static void encryptECB(
            String inputFileName,
            byte[] key,
            String algorithm,
            String outputFileName,
            int mode) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        File inputFile = new File(inputFileName);
        if(!inputFile.exists())
            throw new RuntimeException("**** NO FILE *****");
        File outputFile = new File(outputFileName);
        if(!outputFile.exists())
            outputFile.createNewFile();

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(outputFile);

        //create the Cipher
        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
        SecretKeySpec secretkey = new SecretKeySpec(key, algorithm);

        //init the cipher
        cipher.init(mode, secretkey);

        byte[] block = new byte[cipher.getBlockSize()];

        while(true) {
            int noBytes = fis.read(block);
            if(noBytes == -1)
                break;
            byte[] cipherBlock = cipher.update(block, 0, noBytes);
            fos.write(cipherBlock);
        }

        //IMPORTANT - get the last cipher block
        byte[] cipherBlock = cipher.doFinal();
        fos.write(cipherBlock);

        fis.close();
        fos.close();
    }

    public static PublicKey getPublicKeyFromX509Certificate(String certFileName) throws CertificateException, IOException, CertificateException {
        File certFile = new File(certFileName);
        if(!certFile.exists())
            throw new RuntimeException("*** NO X509 certificate file ***");
        FileInputStream fis = new FileInputStream(certFile);

        CertificateFactory certFactory =
                CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(fis);

        fis.close();

        return certificate.getPublicKey();
    }

    public static byte[] encryptRSA(Key key, byte[] content) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(content);
    }

    public static void writeToBinaryFile(byte[] content, String fileName) throws IOException {
        File file = new File(fileName);
        if (!file.exists())
            file.createNewFile();
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(content);
    }

    public static KeyStore getKeyStore(
            String ksFileName, String ksPass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        File ksFile = new File(ksFileName);
        if(!ksFile.exists())
            throw new RuntimeException("NO KS file !!!");
        FileInputStream fis = new FileInputStream(ksFile);

        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(fis,ksPass.toCharArray());

        fis.close();

        return ks;
    }

    // alias Pass is the same as KS Pass for pkcs12
    public static PrivateKey getPrivateKey(
            KeyStore ks,
            String alias, String aliasPass) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        if(ks == null || !ks.containsAlias(alias))
            throw new RuntimeException("*** NO KS or alias ***");

        //In production don't - use the private key inside the HSM
        PrivateKey pk = (PrivateKey) ks.getKey(alias, aliasPass.toCharArray());
        return pk;
    }

    public static byte[] generateDigitalSignature(
            String fileName, PrivateKey privKey, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        File file = new File(fileName);
        if(!file.exists())
            throw new RuntimeException("*** NO File ***");
        FileInputStream fis = new FileInputStream(file);
        BufferedInputStream bis = new BufferedInputStream(fis);

        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privKey);

        byte[] buffer = new byte[32];
        while (true) {
            int noOfBytes = bis.read(buffer);
            if(noOfBytes == -1)
                break;
            signature.update(buffer, 0, noOfBytes);
        }

        bis.close();

        return signature.sign();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException, CertificateException, KeyStoreException, UnrecoverableKeyException, SignatureException {
        byte[] key = generateSecureRandomKey("AES", 128);
        System.out.println("AES 128 bit key: " + toBase64(key));
        encryptECB("response.txt", key, "AES", "response.sec", Cipher.ENCRYPT_MODE);
        // for verification:
        encryptECB("response.sec", key, "AES", "response_initial.txt", Cipher.DECRYPT_MODE);

        // then I will generate an RSA public-private keypair using keytool:
        // keytool.exe -genkey -keyalg RSA -alias afgkey -keypass passafg -storepass passks -keystore afgkeystore.ks -dname "cn=AFG, ou=AFG, o=Adrian-Florin Gurau, c=RO"
        // or this command if you don't have the JDK bin in PATH and also running in PowerShell:
        // & "C:\Program Files\Java\jdk-25\bin\keytool.exe" -genkey -keyalg RSA -alias afgkey -keypass passafg -storepass passks -keystore afgkeystore.ks -dname "cn=AFG, ou=AFG, o=Adrian-Florin Gurau, c=RO"
        // -- GOT THIS --
        // Warning:  Different store and key passwords not supported for PKCS12 KeyStores. Ignoring user-specified -keypass value.
        // Generating 3072-bit RSA key pair and self-signed certificate (SHA384withRSA) with a validity of 90 days
        //         for: CN=AFG, OU=AFG, O=Adrian-Florin Gurau, C=RO

        PublicKey professorPubKey = getPublicKeyFromX509Certificate("SimplePGP_ISM.cer");
        byte[] encryptedKey = encryptRSA(professorPubKey, key);
        System.out.println("RSA-encrypted AES 128 bit key: " + toBase64(encryptedKey));
        writeToBinaryFile(encryptedKey, "aes_key.sec");

        // I need to send the RSA-encrypted AES key, the AES-encrypted response and my public certificate
        // so, I need to export my public certificate from the keystore:
        // keytool.exe -export -alias afgkey -file AdrianFlorinGurauX509.cer -keystore afgkeystore.ks -storepass passks
        // or the command that I used:
        // & "C:\Program Files\Java\jdk-25\bin\keytool.exe" -export -alias afgkey -file AdrianFlorinGurauX509.cer -keystore afgkeystore.ks -storepass passks

        KeyStore ks = getKeyStore("afgkeystore.ks", "passks");
        PrivateKey privKey = getPrivateKey(ks, "afgkey", "passks");
        System.out.println("AFG Private Key: " + toBase64(privKey.getEncoded()));
        byte[] signature = generateDigitalSignature("response.sec", privKey, "SHA384withRSA");
        System.out.println("SHA384withRSA signature: " + toBase64(signature));
        writeToBinaryFile(signature, "signature.ds");
    }
}
