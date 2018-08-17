/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.apksig.internal.util;

import com.android.apksig.internal.asn1.Asn1BerParser;
import com.android.apksig.internal.asn1.Asn1DecodingException;
import com.android.apksig.internal.asn1.Asn1DerEncoder;
import com.android.apksig.internal.asn1.Asn1EncodingException;
import com.android.apksig.internal.x509.Certificate;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Provides methods to generate {@code X509Certificate}s from their encoded form. These methods
 * can be used to generate certificates that would be rejected by the Java
 * {@code CertificateFactory}.
 */
public class X509CertificateUtils {

    private static CertificateFactory sCertFactory = null;

    /**
     * Generates an {@code X509Certificate} from the encoded form.
     *
     * @throws CertificateException if the encodedForm cannot be decoded to a valid certificate.
     */
    public static X509Certificate generateCertificate(byte[] encodedForm)
            throws CertificateException {
        if (sCertFactory == null) {
            try {
                sCertFactory = CertificateFactory.getInstance("X.509");
            } catch (CertificateException e) {
                throw new RuntimeException("Failed to create X.509 CertificateFactory", e);
            }
        }
        return generateCertificate(encodedForm, sCertFactory);
    }

    /**
     * Generates an {@code X509Certificate} from the encoded form using the provided
     * {@code CertificateFactory}.
     *
     * @throws CertificateException if the encodedForm cannot be decoded to a valid certificate.
     */
    public static X509Certificate generateCertificate(byte[] encodedForm,
            CertificateFactory certFactory) throws CertificateException {
        X509Certificate certificate;
        try {
            certificate =
                    (X509Certificate) certFactory.generateCertificate(
                            new ByteArrayInputStream(encodedForm));
            return certificate;
        } catch (CertificateException e) {
            // This could be expected if the certificate is encoded using a BER encoding that does
            // not use the minimum number of bytes to represent the length of the contents; attempt
            // to decode the certificate using the BER parser and re-encode using the DER encoder
            // below.
        }
        try {
            Certificate reencodedCert = Asn1BerParser.parse(ByteBuffer.wrap(encodedForm),
                    Certificate.class);
            byte[] reencodedForm = Asn1DerEncoder.encode(reencodedCert);
            certificate = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(reencodedForm));
            return certificate;
        } catch (Asn1DecodingException | Asn1EncodingException | CertificateException e) {
            throw new CertificateException("Failed to parse certificate", e);
        }
    }

}
