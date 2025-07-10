package com.meteorkim.x509pki;

import org.springframework.data.jpa.repository.JpaRepository;

public interface CertificatePolicyRepository extends JpaRepository<CertificatePolicy, Integer> {
    boolean existsByPolicyName(String name);
}
