package com.example.demo;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class KeyStoreTestMain {

    public static final String SCP_OCP_APP_ALIAS = "scpocpappalias";

    public static void main(String[] args) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnrecoverableEntryException {
        JavaKeyStore javaKeyStore
                = new JavaKeyStore(KeyStore.getDefaultType(), "ocppocstorepassword", "ocpstore");



        String secretKeyPassword = "ocppocsecretpassword";
        String secretKeySalt = "123456789";
        int secretKeyIvSize = 16;


        SymmetricKeyService symmetricKeyService = new SymmetricKeyService(secretKeyPassword,secretKeySalt,secretKeyIvSize);

      // oneTimeSetup(javaKeyStore, secretKeyPassword, symmetricKeyService);


        encryptDecryptEverytime(javaKeyStore, symmetricKeyService);

    }

    private static void encryptDecryptEverytime(JavaKeyStore javaKeyStore, SymmetricKeyService symmetricKeyService) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, CertificateException, IOException {
        javaKeyStore.loadKeyStore();

        SecretKey key = (SecretKey) javaKeyStore.getEntry(SCP_OCP_APP_ALIAS);

        String message = "Test message";
        String encrypt = symmetricKeyService.encrypt(message.getBytes(), key);
        System.out.println("encrypted message:"+ encrypt);

        String decrypt = symmetricKeyService.decrypt(encrypt, key);
        System.out.println("decrypted message:"+decrypt);
    }

    private static void oneTimeSetup(JavaKeyStore javaKeyStore, String secretKeyPassword, SymmetricKeyService symmetricKeyService) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        // one time activity - start
        javaKeyStore.createEmptyKeyStore();
        storeSecretKeyInKeystore(javaKeyStore, secretKeyPassword, symmetricKeyService);
        // one time activity - end
    }

    private static SecretKey storeSecretKeyInKeystore(JavaKeyStore javaKeyStore, String secretKeyPassword
            , SymmetricKeyService symmetricKeyService) throws NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException {
        SecretKey secretKey = symmetricKeyService.generateSecretKey();
        KeyStore.SecretKeyEntry secret   = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter password = new KeyStore.PasswordProtection(secretKeyPassword.toCharArray());

        javaKeyStore.setEntry(SCP_OCP_APP_ALIAS, secret, password);
        return secretKey;
    }


}
