package com.meteorkim.x509pki;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class SoftwareCryptoProvider implements CryptoProvider {

    private final String keystoreFile;
    private final char[] keystorePassword;
    private KeyStore keyStore;
    private final Map<String, PrivateKey> transientKeys = new HashMap<>();

    public SoftwareCryptoProvider(String keystoreFile, String keystorePassword) {
        this.keystoreFile = keystoreFile;
        this.keystorePassword = keystorePassword.toCharArray();
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public void load() throws Exception {
        this.keyStore = KeyStore.getInstance("PKCS12");
        File ksFile = new File(keystoreFile);
        if (ksFile.exists()) {
            try (FileInputStream fis = new FileInputStream(ksFile)) {
                keyStore.load(fis, keystorePassword);
            }
        } else {
            keyStore.load(null, keystorePassword);
        }
    }

    @Override
    public boolean isKeyExists(String alias) throws KeyStoreException {
        return keyStore.isKeyEntry(alias);
    }

    @Override
    public PublicKey generateKeyPair(String alias, int keySize) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(keySize, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();
        transientKeys.put(alias, keyPair.getPrivate());
        return keyPair.getPublic();
    }

    @Override
    public ContentSigner getContentSigner(String alias) throws Exception {
        PrivateKey privateKey = transientKeys.get(alias);
        if (privateKey == null) {
            privateKey = (PrivateKey) keyStore.getKey(alias, keystorePassword);
        }
        if (privateKey == null) {
            throw new KeyStoreException("Key for alias '" + alias + "' not found");
        }
        return new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(privateKey);
    }

    @Override
    public void storeKeyAndCertificateChain(String alias, X509Certificate[] chain) throws Exception{
        PrivateKey privateKey = transientKeys.get(alias);
        if (privateKey == null) {
            throw new KeyStoreException("Key for alias '" + alias + "' not found");
        }

        keyStore.setKeyEntry(alias, privateKey, keystorePassword, chain);

        // 저장 후 임시 저장소에서 제거
        transientKeys.remove(alias);
    }

    @Override
    public void save() throws Exception{
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            keyStore.store(fos, keystorePassword);
        }
    }
}
