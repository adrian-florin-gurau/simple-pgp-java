package ro.ase.ism.sap.adrian.florin.gurau;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class VerifyReceivedMessages {
    public static byte[] getDigitalSignatureFromFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            return null;
        }
        FileInputStream fis = new FileInputStream(file);
        BufferedInputStream bis = new BufferedInputStream(fis);
        byte[] buffer = new byte[32];
        byte[] signature = new byte[bis.available()];
        int i = 0;
        while (true) {
            int noOfBytes = bis.read(buffer);
            if (noOfBytes == -1) {
                break;
            }
            for (int j = 0; j < noOfBytes; j++) {
                signature[i++] = buffer[j];
            }
        }
        bis.close();
        return signature;
    }

    public static String signatureAsBase64(byte[] signature) {
        if (signature == null) {
            return null;
        }
        return Base64.getEncoder().encodeToString(signature);
    }

    public static Map<String, byte[]> getDigitalSignaturesFromFiles(List<String> filePaths) throws IOException {
        Map<String, byte[]> digitalSignatures = new HashMap<>();
        for (String filePath : filePaths) {
            digitalSignatures.put(filePath, getDigitalSignatureFromFile(filePath));
        }
        return digitalSignatures;
    }

    public static Map<String, String> signaturesAsBase64(Map<String, byte[]> signatures) {
        Map<String, String> digitalSignatures = new HashMap<>();
        for (var entry : signatures.entrySet()) {
            digitalSignatures.put(entry.getKey(), signatureAsBase64(entry.getValue()));
        }
        return digitalSignatures;
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

    public static boolean validateSignature(
            String fileName,
            byte[] digitalSignature,
            PublicKey pubKey,
            String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        File file = new File(fileName);
        if(!file.exists())
            throw new RuntimeException("*** NO File ***");
        FileInputStream fis = new FileInputStream(file);
        BufferedInputStream bis = new BufferedInputStream(fis);

        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(pubKey);

        byte[] buffer = new byte[32];
        while (true) {
            int noOfBytes = bis.read(buffer);
            if (noOfBytes == -1) {
                break;
            }
            signature.update(buffer, 0, noOfBytes);
        }

        return signature.verify(digitalSignature);
    }

    public static Map<String, byte[]> getReadyForValidation(Map<String, byte[]> signatures, String signatureExtension, String fileExtension) {
        Map<String, byte[]> readyForValidation = new HashMap<>();
        for (var entry : signatures.entrySet()) {
            readyForValidation.put(entry.getKey().replace(signatureExtension, fileExtension), entry.getValue());
        }
        return readyForValidation;
    }

    public static Map<String, Boolean> validateSignatures(
            Map<String, byte[]> filesAndSignatures,
            PublicKey pubKey,
            String algorithm) throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeyException {
        Map<String, Boolean> signaturesValidity = new HashMap<>();
        for (var entry : filesAndSignatures.entrySet()) {
            signaturesValidity.put(entry.getKey(), validateSignature(entry.getKey(), entry.getValue(), pubKey, algorithm));
        }
        return signaturesValidity;
    }

    public static String getTheValidFileName(Map<String, Boolean> filesValidations) {
        for (var entry : filesValidations.entrySet()) {
            if (entry.getValue().equals(true)) {
                return entry.getKey();
            }
        }
        return null;
    }

    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        List<String> filePaths = List.of(
                "SAPExamSubject1.signature",
                "SAPExamSubject2.signature",
                "SAPExamSubject3.signature"
        );
        System.out.println("\nThe files digital signatures:");
        Map<String, byte[]> filesAndDigitalSignatures = getDigitalSignaturesFromFiles(filePaths);
        signaturesAsBase64(filesAndDigitalSignatures).forEach((k, v) -> System.out.println(k + ": " + v));
        PublicKey pubKey = getPublicKeyFromX509Certificate("SimplePGP_ISM.cer");
        Map<String, byte[]> signaturesForVerification = getReadyForValidation(filesAndDigitalSignatures, ".signature", ".txt");
        Map<String, Boolean> filesValidations = validateSignatures(signaturesForVerification, pubKey, "SHA512withRSA");
        System.out.println("\nThe files signature validity:");
        System.out.println(filesValidations);
        String theOriginalMessage = getTheValidFileName(filesValidations);
        System.out.println("\nThe original message is in file: " + (theOriginalMessage != null ? theOriginalMessage : "NONE"));
    }
}