package com.meteorkim.x509pki.crypto;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.operator.ContentSigner;

public interface CryptoProvider {

    void load() throws Exception;

    boolean isKeyExists(String alias) throws Exception;

    PublicKey generateKeyPair(String alias, int keySize) throws Exception;

    ContentSigner getContentSigner(String alias) throws Exception;

    void storeKeyAndCertificateChain(String alias, X509Certificate[] chain) throws Exception;

    void save() throws Exception;
}
