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
import com.android.apksig.util.DataSinks;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * VerityTreeBuilder is used to generate the root hash of verity tree built from the input file.
 * The root hash can be used on device for on-access verification.  The tree itself is reproducible
 * on device, and is not shipped with the APK.
 */
public class VerityTreeBuilder {

    /** Maximum size (in bytes) of each node of the tree. */
    private final static int CHUNK_SIZE = 4096;

    /** Digest algorithm (JCA Digest algorithm name) used in the tree. */
    private final static String JCA_ALGORITHM = "SHA-256";

    /** Optional salt to apply before each digestion. */
    private final byte[] mSalt;

    public VerityTreeBuilder(byte[] salt) {
        mSalt = salt;
    }

    /**
     * Returns the root hash of the verity tree built from the data source.
     *
     * The tree is built bottom up. The bottom level has 256-bit digest for each 4 KB block in the
     * input file.  If the total size is larger than 4 KB, take this level as input and repeat the
     * same procedure, until the level is within 4 KB.  If salt is given, it will apply to each
     * digestion before the actual data.
     *
     * The returned root hash is calculated from the last level of 4 KB chunk, similarly with salt.
     *
     * The tree is currently stored only in memory and is never written out.  Nevertheless, it is
     * the actual verity tree format on disk, and is supposed to be re-generated on device.
     */
    public byte[] generateVerityTreeRootHash(DataSource fileSource)
            throws IOException, NoSuchAlgorithmException {
        if (fileSource.size() > Integer.MAX_VALUE) {
            throw new UnsupportedOperationException("Input file is bigger than Integer.MAX_VALUE");
        }

        MessageDigest md = MessageDigest.getInstance(JCA_ALGORITHM);
        int digestSize = md.getDigestLength();

        // Calculate the summed area table of level size. In other word, this is the offset
        // table of each level, plus the next non-existing level.
        int[] levelOffset = calculateLevelOffset((int) fileSource.size(), digestSize);

        ByteBuffer verityBuffer = ByteBuffer.allocate(levelOffset[levelOffset.length - 1]);

        // Generate the hash tree bottom-up.
        for (int i = levelOffset.length - 2; i >= 0; i--) {
            DataSource src;
            if (i == levelOffset.length - 2) {
                src = fileSource;
            } else {
                src = DataSources.asDataSource(slice(verityBuffer.asReadOnlyBuffer(),
                            levelOffset[i + 1], levelOffset[i + 2]));
            }

            DataSink middleBufferSink = new ByteBufferSink(
                    slice(verityBuffer, levelOffset[i], levelOffset[i + 1]));

            DigestSink chunkedDigestSink = new DigestSink(middleBufferSink, md, mSalt);
            feedDataByChunks(src, chunkedDigestSink);

            // If the output is not full chunk, pad with 0s.
            int incomplete = (int) (chunkedDigestSink.getTotalOutputBytes() % CHUNK_SIZE);
            if (incomplete > 0) {
                byte[] padding = new byte[CHUNK_SIZE - incomplete];
                middleBufferSink.consume(padding, 0, padding.length);
            }
        }

        // Finally, calculate the root hash from the top level (only page).
        ByteBuffer firstPage = slice(verityBuffer.asReadOnlyBuffer(), 0, CHUNK_SIZE);
        ByteArrayDataSink rootHashSink = new ByteArrayDataSink(digestSize);
        new DigestSink(rootHashSink, md, mSalt).consume(firstPage);
        if (rootHashSink.size() != digestSize) {
            throw new RuntimeException("Root hash digest size mismatch: " +
                    rootHashSink.size() + " != " + digestSize);
        }
        return rootHashSink.getByteBuffer(0, digestSize).array();
    }

    /**
     * Returns an array of summed area table of level size in the verity tree.  In other words, the
     * returned array is offset of each level in the verity tree file format, plus an additional
     * offset of the next non-existing level (i.e. end of the last level + 1).  Thus the array size
     * is level + 1.
     */
    private static int[] calculateLevelOffset(int dataSize, int digestSize) {
        // Compute total size of each level, bottom to top.
        ArrayList<Integer> levelSize = new ArrayList<>();
        while (true) {
            int chunkCount = divideRoundup(dataSize, CHUNK_SIZE);
            levelSize.add(CHUNK_SIZE * divideRoundup(chunkCount * digestSize, CHUNK_SIZE));
            if (chunkCount * digestSize <= CHUNK_SIZE) {
                break;
            }
            dataSize = chunkCount * digestSize;
        }

        // Reverse and convert to summed area table.
        int[] levelOffset = new int[levelSize.size() + 1];
        levelOffset[0] = 0;
        for (int i = 0; i < levelSize.size(); i++) {
            levelOffset[i + 1] = levelOffset[i] + levelSize.get(levelSize.size() - i - 1);
        }
        return levelOffset;
    }

    /**
     * Chunks data source into units then feeds them to the sink one by one.  If the last unit is
     * less than the chunk size, feed with extra padding 0 to fill up the chunk.
     */
    private static void feedDataByChunks(DataSource dataSource, DataSink dataSink)
            throws IOException {
        long size = dataSource.size();
        long offset = 0;
        for (; offset + CHUNK_SIZE <= size; offset += CHUNK_SIZE) {
            dataSource.feed(offset, CHUNK_SIZE, dataSink);
        }

        // Send the last incomplete chunk with 0 padding to the sink at once.
        int remaining = (int) (size % CHUNK_SIZE);
        if (remaining > 0) {
            ByteBuffer buffer = ByteBuffer.allocate(CHUNK_SIZE);  // initialized to 0.
            dataSource.copyTo(offset, remaining, buffer);
            buffer.rewind();
            dataSink.consume(buffer);
        }
    }

    /** Divides a number and round up to the closest integer. */
    private static int divideRoundup(int dividend, int divisor) {
        return (dividend + divisor - 1) / divisor;
    }

    /** Returns a slice of the buffer with shared the content. */
    private static ByteBuffer slice(ByteBuffer buffer, int begin, int end) {
        ByteBuffer b = buffer.duplicate();
        b.position(begin);
        b.limit(end);
        return b.slice();
    }
}
