package com.example.demo;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class SymmetricKeyService {


    public String ALGORITHM = "AES/CBC/PKCS5Padding";
    private String secretKeyPassword;
    private String secretKeySalt;

    private IvParameterSpec ivParameterSpec;

    public SymmetricKeyService(String secretKeyPassword, String secretKeySalt, int IVSize) {
        this.secretKeyPassword = secretKeyPassword;
        this.secretKeySalt = secretKeySalt;

        byte[] iv = new byte[IVSize];
        new SecureRandom().nextBytes(iv);
        ivParameterSpec =  new IvParameterSpec(iv);
    }


    public SecretKey generateSecretKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(secretKeyPassword.toCharArray(), secretKeySalt.getBytes(), 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), "AES");
    }

    public String encrypt(byte[] rawText, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            BadPaddingException, IllegalBlockSizeException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] cipherText = cipher.doFinal(rawText);
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public String decrypt(String cipherText, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

}
