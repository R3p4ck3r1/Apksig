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

package com.android.apksig;

import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.v3.V3SchemeSigner;
import com.android.apksig.internal.apk.v3.V3SigningCertificateLineage;
import com.android.apksig.internal.apk.v3.V3SigningCertificateLineage.SigningCertificateNode;
import com.android.apksig.internal.util.Pair;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * APK Signer Lineage.
 *
 * <p>The signer lineage contains a history of signing certificates with each ancestor attesting to
 * the validity of its descendant.  Each additional descendant represents a new identity that can be
 * used to sign an APK, and each generation has accompanying attributes which represent how the
 * APK would like to view the older signing certificates, specifically how they should be trusted in
 * certain situations.
 *
 * <p> Its primary use is to enable APK Signing Certificate Rotation.  The Android platform verifies
 * the APK Signer Lineage, and if the current signing certificate for the APK is in the Signer
 * Lineage, and the Lineage contains the certificate the platform associates with the APK, it will
 * allow upgrades to the new certificate.
 *
 * <p>Use {@link Builder} to obtain instances of this signer.
 *
 * @see <a href="https://source.android.com/security/apksigning/index.html">Application Signing</a>
 */
public class SigningCertificateLineage {

    private final static int MAGIC = 0x3eff39d1;

    private final static int FIRST_VERSION = 1;

    private int mVersion = FIRST_VERSION;

    private final int mMinSdkVersion;

    private List<SigningCertificateNode> mLineage;

    /**
     * the signing lineage is just a list of nodes, with the first being the original signing
     * certificate and the most recent being the one with which the APK is to actually be signed.
     */
    private final List<SigningCertificateNode> mSigningLineage;

    private SigningCertificateLineage(ByteBuffer inputByteBuffer, int minSdkVersion)
            throws IOException {
        mMinSdkVersion = minSdkVersion;
        mSigningLineage = new ArrayList<>();
        mLineage = read(inputByteBuffer);
    }

    private List<SigningCertificateNode> read(ByteBuffer inputByteBuffer)
            throws IOException {
        ApkSigningBlockUtils.checkByteOrderLittleEndian(inputByteBuffer);
        if (inputByteBuffer.remaining() < 8) {
            throw new IllegalArgumentException(
                    "Improper SigningCertificateLineage format: insufficient data for header.");
        }

        if (inputByteBuffer.getInt() != MAGIC) {
            throw new IllegalArgumentException(
                    "Improper SigningCertificateLineage format: MAGIC header mismatch.");
        }
        return read(inputByteBuffer, inputByteBuffer.getInt());


    }

    private List<SigningCertificateNode> read(ByteBuffer inputByteBuffer, int version)
            throws IOException {
        switch (version) {
            case FIRST_VERSION:
                mVersion = FIRST_VERSION;
                return V3SigningCertificateLineage.readSigningCertificateLineage(inputByteBuffer);
            default:
                throw new IllegalArgumentException(
                        "Improper SigningCertificateLineage format: unrecognized version.");
        }
    }

    public ByteBuffer write() {
        byte[] encodedLineage =
                V3SigningCertificateLineage.encodeSigningCertificateLineage(mSigningLineage);
        int payloadSize = 4 + 4 + encodedLineage.length;
        ByteBuffer result = ByteBuffer.allocate(payloadSize);
        result.order(ByteOrder.LITTLE_ENDIAN);
        result.putInt(MAGIC);
        result.putInt(mVersion);
        result.put(encodedLineage);
        return result;
    }

    public byte[] generateV3SignerAttribute() {
        // FORMAT (little endian):
        // * length-prefixed bytes: attribute pair
        //   * uint32: ID
        //   * bytes: value - encoded V3 SigningCertificateLineage
        byte[] encodedLineage =
                V3SigningCertificateLineage.encodeSigningCertificateLineage(mSigningLineage);
        int payloadSize = 4 + 4 + encodedLineage.length;
        ByteBuffer result = ByteBuffer.allocate(payloadSize);
        result.order(ByteOrder.LITTLE_ENDIAN);
        result.putInt(4 + encodedLineage.length);
        result.putInt(V3SchemeSigner.PROOF_OF_ROTATION_ATTR_ID);
        result.put(encodedLineage);
        return result.array();
    }

    // TODO add API to return all signing certificate(s)

    // TODO add API to query if given signing certificate is in set of signing certificates

    // TODO add API to modify flags corresponding to a given signing certificate

    private int calculateDefaultFlags() {
        /// TODO calculate default flags based on minSdkVersion
        throw new UnsupportedOperationException("Default flag values not yet implemented");
    }

    public void spawnDescendant(SignerConfig parent, SignerConfig child)
            throws CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException,
                    SignatureException {
        int flags = calculateDefaultFlags();
        spawnDescendant(parent, flags, child, flags);
    }

    public void spawnDescendant(
            SignerConfig parent, int parentFlags, SignerConfig child, int childFlags)
                    throws CertificateEncodingException, InvalidKeyException,
                            NoSuchAlgorithmException, SignatureException {
        if (mLineage == null || mLineage.size() == 0) {
            // no history yet, begin a new dynasty
            spawnFirstDescendant(parent, parentFlags);
        }
        // make sure that the parent matches our newest generation (leaf node/sink)
        SigningCertificateNode currentGeneration = mLineage.get(mLineage.size() - 1);
        if (!Arrays.equals(currentGeneration.signingCert.getEncoded(),
                parent.getCertificate().getEncoded())) {
            throw new IllegalArgumentException("SignerConfig Certificate containing private key"
                    + " to sign the new SigningCertificateLineage record does not match the"
                    + " existing most recent record");
        }

        // create data to be signed
        ByteBuffer prefixedSignedData = ByteBuffer.wrap(
                V3SigningCertificateLineage.encodeSignedData(
                        child.getCertificate(), childFlags));
        prefixedSignedData.position(4);
        byte[] signedData = prefixedSignedData.slice().array();

        // create SignerConfig to do the signing
        List<X509Certificate> certificates = new ArrayList<>(1);
        certificates.add(parent.getCertificate());
        ApkSigningBlockUtils.SignerConfig newSignerConfig =
                new ApkSigningBlockUtils.SignerConfig();
        newSignerConfig.privateKey = parent.getPrivateKey();
        newSignerConfig.certificates = certificates;
        newSignerConfig.signatureAlgorithms = new ArrayList<>();
        newSignerConfig.signatureAlgorithms.add(getSignatureAlgorithm(parent));

        // sign it
        List<Pair<Integer, byte[]>> signatures =
                ApkSigningBlockUtils.generateSignaturesOverData(newSignerConfig, signedData);

        // finally, add it to our lineage
        SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.findById(signatures.get(0).getFirst());
        byte[] signature = signatures.get(0).getSecond();
        currentGeneration.sigAlgorithm = sigAlgorithm;
        SigningCertificateNode childNode =
                new SigningCertificateNode(
                        child.getCertificate(), sigAlgorithm, null, signature, childFlags);
        mLineage.add(childNode);
    }

    private SignatureAlgorithm getSignatureAlgorithm(SignerConfig parent)
            throws InvalidKeyException {
        PublicKey publicKey = parent.getCertificate().getPublicKey();

        // TODO switch to won signature algorithm selection, or add support for multiple algorithms
        List<SignatureAlgorithm> algorithms = V3SchemeSigner.getSuggestedSignatureAlgorithms(
                publicKey, mMinSdkVersion,false /* padding support */);
        return algorithms.get(0);
    }

    public void spawnFirstDescendant(SignerConfig parent, int flags) {
        if (mLineage == null) {
            mLineage = new ArrayList<>();
        }
        if (mLineage.size() > 0) {
            throw new IllegalStateException("SigningCertificateLineage already has its first node");
        }
        // create "fake" signed data (there will be no signature over it, since there is no parent
        SigningCertificateNode firstNode = new SigningCertificateNode(
                parent.getCertificate(), null, null, new byte[0], flags);
        mLineage.add(firstNode);
    }

    /**
     * Builder of an {@code SigningCertificateLineage}.
     */
    public static class Builder {

        private int mMinimumSdkVersion;

        /**
         * an existing, to-be-deserialized {@link SigningCertificateLineage}, to which a new entry
         * may be appended.
         */
        private ByteBuffer mInputSigningCertificateLineage;

        /**
         * Constructs a new {@code Builder} for an {@code V3SigningCertificateLineage} which contains proof of
         * signing certificate rotation.  The builder may be used to modify the attributes for
         * chosen signing certificates, or to create a new descendant signing certificate.
         */
        public Builder() {
        }

        /**
         * Set the source from which to build an extant {@code V3SigningCertificateLineage}
         */
        public Builder setInputSigningCertificateLineage(ByteBuffer inputSigningCertificateLineage) {
            mInputSigningCertificateLineage = inputSigningCertificateLineage;
            return this;
        }

        /**
         * Specify the minimum SDK version with which this {@code V3SigningCertificateLineage} is
         * expected to work: all signing algorithms used in this lineage need to be supported.
         */
        public Builder setMinimumSdkVersion(int minimumSdkVersion) {
            mMinimumSdkVersion = minimumSdkVersion;
            return this;
        }

        public SigningCertificateLineage build() throws IOException {
            return new SigningCertificateLineage(
                    mInputSigningCertificateLineage, mMinimumSdkVersion);
        }
    }

    /**
     * Configuration of a signer.  Used to add a new entry to the {@link SigningCertificateLineage}
     *
     * <p>Use {@link Builder} to obtain configuration instances.
     */
    public static class SignerConfig {
        private final PrivateKey mPrivateKey;
        private final X509Certificate mCertificate;

        private SignerConfig(
                PrivateKey privateKey,
                X509Certificate certificate) {
            mPrivateKey = privateKey;
            mCertificate = certificate;
        }

        /**
         * Returns the signing key of this signer.
         */
        public PrivateKey getPrivateKey() {
            return mPrivateKey;
        }

        /**
         * Returns the certificate(s) of this signer. The first certificate's public key corresponds
         * to this signer's private key.
         */
        public X509Certificate getCertificate() {
            return mCertificate;
        }

        /**
         * Builder of {@link SignerConfig} instances.
         */
        public static class Builder {
            private final PrivateKey mPrivateKey;
            private final X509Certificate mCertificate;

            /**
             * Constructs a new {@code Builder}.
             *
             * @param privateKey signing key
             * @param certificate the X.509 certificate with a subject public key of the
             * {@code privateKey}.
             */
            public Builder(
                    PrivateKey privateKey,
                    X509Certificate certificate) {
                mPrivateKey = privateKey;
                mCertificate = certificate;
            }

            /**
             * Returns a new {@code SignerConfig} instance configured based on the configuration of
             * this builder.
             */
            public SignerConfig build() {
                return new SignerConfig(
                        mPrivateKey,
                        mCertificate);
            }
        }
    }
}
