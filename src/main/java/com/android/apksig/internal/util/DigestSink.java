/*
 * Copyright (C) 2017 The Android Open Source Project
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

import com.android.apksig.util.DataSink;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;

/**
 * A proxy data sink that feed the digest of the consumed data to the actual sink.  Each consume
 * operation is digested at once, then the digest is feed to the actual sink.
 *
 * If salt is given, it applies before the data to digest.
 */
public class DigestSink implements DataSink {

    private final DataSink mRealSink;
    private final MessageDigest mMd;
    private final byte[] mSalt;

    private long mTotalOutputBytes = 0;

    public DigestSink(DataSink realSink, MessageDigest messageDigest, byte[] salt) {
        mRealSink = realSink;
        mMd = messageDigest;
        mSalt = salt;
    }

    @Override
    public void consume(byte[] buf, int offset, int length) throws IOException {
        consume(ByteBuffer.wrap(buf, offset, length));
    }

    @Override
    public void consume(ByteBuffer buf) throws IOException {
        mMd.reset();
        if (mSalt != null) {
            mMd.update(mSalt);
        }
        mMd.update(buf);
        byte[] digest = mMd.digest();
        mRealSink.consume(ByteBuffer.wrap(digest));

        mTotalOutputBytes += digest.length;
    }

    /** Returns the total bytes feeded to the actual sink. */
    public long getTotalOutputBytes() {
        return mTotalOutputBytes;
    }
}
