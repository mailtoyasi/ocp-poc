package com.example.demo;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

import static com.example.demo.CommonConstants.*;

public class OCPKeyStoreUtility {


    public static void main(String[] args) throws Exception {
        String secretKeySalt = "456788";
        int secretKeyIvSize = 16;

        SymmetricKeyService symmetricKeyService = new SymmetricKeyService(KEY_STORE_PASSWORD,secretKeySalt,secretKeyIvSize);
        // oneTimeSetupToStoreSecretKeysInKeystore(symmetricKeyService);
          readSecretKeysFromKeyStoreThenPeformEncryptionDecryption(symmetricKeyService);
    }

    private static void readSecretKeysFromKeyStoreThenPeformEncryptionDecryption(SymmetricKeyService symmetricKeyService) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        SecretKey secretKey = loadKeyStore(SECRETE_KEY_ALIAS);

        String message = "Test message";
        String encrypt = symmetricKeyService.encrypt(message.getBytes(), secretKey);
        System.out.println("encrypted message:"+ encrypt);

        String decrypt = symmetricKeyService.decrypt(encrypt, secretKey);
        System.out.println("decrypted message:"+decrypt);
    }

    private static void oneTimeSetupToStoreSecretKeysInKeystore(SymmetricKeyService symmetricKeyService) throws NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, IOException, CertificateException {
        SecretKey secretKey = symmetricKeyService.generateSecretKey();
        createKeyStore(secretKey);
    }

    public static void createKeyStore(SecretKey secretKey) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
        keyStore.load(null, KEY_STORE_PASSWORD.toCharArray());

        KeyStore.SecretKeyEntry secretKeyEntry   = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(SECRET_KEY_PASSWORD.toCharArray());
        keyStore.setEntry(SECRETE_KEY_ALIAS, secretKeyEntry, protectionParameter);

        File file = new File(KEY_STORE_NAME);
        try(FileOutputStream fos = new FileOutputStream(file);) {
            keyStore.store(fos, KEY_STORE_PASSWORD.toCharArray());
        }

        printKeyStoreEntries(keyStore);
    }

    public static SecretKey loadKeyStore(String keyalias) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance(KEY_STORE_TYPE);
        InputStream readStream = new FileInputStream(KEY_STORE_NAME);
        ks.load(readStream, KEY_STORE_PASSWORD.toCharArray());

        printKeyStoreEntries(ks);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(SECRET_KEY_PASSWORD.toCharArray());
        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(keyalias, protectionParameter);
        SecretKey secretKey = entry.getSecretKey();
        System.out.println(secretKey.getAlgorithm());
        return secretKey;
    }

    private static void printKeyStoreEntries(KeyStore ks) throws KeyStoreException {
        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements()) {
            String s = aliases.nextElement();
            System.out.println("alias:"+s);
        }

    }
}
