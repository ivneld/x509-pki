package com.meteorkim.x509pki;

import java.util.Collections;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Component
@Order(1) // CaChainInitializer 보다 먼저 실행되도록 순서 지정
@RequiredArgsConstructor
public class DefaultPolicyInitializer implements CommandLineRunner {

    private final CertificatePolicyRepository repository;

    @Override
    public void run(String... args) throws Exception {
        createDefaultPolicies();
    }

    private void createDefaultPolicies() {
        createPolicyIfNotExists("DEFAULT_ROOT_CA", CertificateType.ROOT_CA, 365 * 20, true, 1, KeyUsage.keyCertSign | KeyUsage.cRLSign, Collections.emptyList());
        createPolicyIfNotExists("DEFAULT_SUB_CA", CertificateType.SUBORDINATE_CA, 365 * 10, true, 0, KeyUsage.keyCertSign | KeyUsage.cRLSign, Collections.emptyList());
        createPolicyIfNotExists("DEFAULT_TLS_LEAF", CertificateType.LEAF, 365, false, null, KeyUsage.digitalSignature | KeyUsage.keyEncipherment,
            List.of(KeyPurposeId.id_kp_serverAuth.getId()));
    }

    private void createPolicyIfNotExists(
        String name,
        CertificateType type,
        long validity,
        boolean isCa,
        Integer pathLen,
        int keyUsage,
        List<String> ekus) {
        if (!repository.existsByPolicyName(name)) {
            CertificatePolicy policy = new CertificatePolicy(name, type, validity, isCa, pathLen, keyUsage, ekus);
            repository.save(policy);
        }
    }
}
