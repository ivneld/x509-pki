package com.meteorkim.x509pki.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CryptoProviderConfig {

    @Bean
    CryptoProvider setProvider(
        @Value("${pki.keystore.path}") String keystorePath,
        @Value("${pki.keystore.password}") String keystorePassword) {

        return new SoftwareCryptoProvider(keystorePath, keystorePassword);
    }
}
