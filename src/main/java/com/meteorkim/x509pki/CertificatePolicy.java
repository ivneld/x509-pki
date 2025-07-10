package com.meteorkim.x509pki;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import java.util.List;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class CertificatePolicy {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String policyName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType type;

    private long validityInDays;
    private boolean isCa;
    private Integer pathLenConstraint;
    private int keyUsage; // Bouncy Castle KeyUsage 비트마스크

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "policy_extended_key_usages", joinColumns = @JoinColumn(name = "policy_id"))
    @Column(name = "oid")
    private List<String> extendedKeyUsageOids;

    public CertificatePolicy(
        String policyName,
        CertificateType type,
        long validityInDays,
        boolean isCa,
        Integer pathLenConstraint,
        int keyUsage,
        List<String>
            extendedKeyUsageOids) {
        this.policyName = policyName;
        this.type = type;
        this.validityInDays = validityInDays;
        this.isCa = isCa;
        this.pathLenConstraint = pathLenConstraint;
        this.keyUsage = keyUsage;
        this.extendedKeyUsageOids = extendedKeyUsageOids;
        validate();
    }

    /**
     * 정책 자체의 유효성을 검증하는 비즈니스 로직
     */
    private void validate() {
        if (isCa && type == CertificateType.LEAF) {
            throw new IllegalStateException("LEAF certificates cannot be a CA.");
        }
        if (!isCa && type != CertificateType.LEAF) {
            throw new IllegalStateException("Only LEAF certificates can have isCa=false.");
        }
        if (pathLenConstraint != null && !isCa) {
            throw new IllegalStateException("pathLenConstraint can only be set for CAs.");
        }
    }
}
