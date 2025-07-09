package com.meteorkim.x509pki;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class CaChainInitializer implements CommandLineRunner {

    private final CryptoProvider cryptoProvider;
    private static final String ROOT_CA_ALIAS = "my-root-ca";
    private static final String SUB_CA_ALIAS = "my-sub-ca";

    @Override
    public void run(String... args) throws Exception {
        cryptoProvider.load();

        if (cryptoProvider.isKeyExists(ROOT_CA_ALIAS)) {
            log.info("CA chain already initialized.");
            return;
        }

        log.info("Initializing new CA chain...");

        // 1. Root CA 생성
        X500Name rootSubject = new X500Name("CN=My Test Root CA, O=My Corp, C=KR");
        PublicKey rootPublicKey = cryptoProvider.generateKeyPair(ROOT_CA_ALIAS, 4096);
        ContentSigner rootSigner = cryptoProvider.getContentSigner(ROOT_CA_ALIAS);
        X509Certificate rootCert = createCertificate(rootSubject, rootSubject, rootPublicKey, rootSigner, 3650, true);
        // Root CA는 체인이 자기 자신이므로, 자기 자신만 포함하는 배열을 만듭니다.
        cryptoProvider.storeKeyAndCertificateChain(ROOT_CA_ALIAS, new X509Certificate[]{rootCert});
        // 2. 중간 CA 생성
        X500Name intermediateSubject = new X500Name("CN=My Test Intermediate CA, O=My Corp, C=KR");
        PublicKey intermediatePublicKey = cryptoProvider.generateKeyPair(SUB_CA_ALIAS, 2048);
        // 서명자는 Root CA
        ContentSigner intermediateIssuerSigner = cryptoProvider.getContentSigner(ROOT_CA_ALIAS);
        X509Certificate intermediateCert = createCertificate(rootSubject, intermediateSubject, intermediatePublicKey, intermediateIssuerSigner, 1825, true);
        // 중간 CA의 체인은 [자신, 상위(Root)] 순서입니다.
        X509Certificate[] intermediateChain = {intermediateCert, rootCert};
        cryptoProvider.storeKeyAndCertificateChain(SUB_CA_ALIAS, intermediateChain);
        // 3. 최종 저장
        cryptoProvider.save();
        System.out.println("New CA chain created and saved successfully.");
    }

    private X509Certificate createCertificate(
        X500Name issuer,
        X500Name subject,
        PublicKey subjectPublicKey,
        ContentSigner signer,
        int days,
        boolean isCa) throws CertIOException, CertificateException {
        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(days, ChronoUnit.DAYS));
        BigInteger serial = new BigInteger(128, new SecureRandom());

        var certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, subjectPublicKey);
        // isCa=true로 설정하여 CA 인증서임을 명시
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        // KeyUsage 확장 : CA 인증서는 다른 인증서와 CRL 서명을 할 수 있어야 함
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
    }
}
