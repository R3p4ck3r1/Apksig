/*
 * Copyright (C) 2019 The Android Open Source Project
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

import static org.junit.Assert.assertArrayEquals;

import com.android.apksig.util.DataSource;
import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class RandomAccessFileDataSourceTest {
    @Rule public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private byte[] fullFileContent;
    private RandomAccessFile raf;

    @Before
    public void setUp() throws Exception {
        File dataFile = temporaryFolder.newFile();

        int fileSize = 1024 * 1024 + 987654;
        fullFileContent = new byte[fileSize];
        for (int i = 0; i < fileSize; ++i) {
            fullFileContent[i] = (byte) (i % 255);
        }
        try (FileOutputStream fos = new FileOutputStream(dataFile)) {
            fos.write(fullFileContent);
        }
        raf = new RandomAccessFile(dataFile, "r");
    }

    @Test
    public void testFeedsCorrectData() throws Exception {
        DataSource rafDataSource = new RandomAccessFileDataSource(raf);

        ByteArrayDataSink dataSink = new ByteArrayDataSink();

        int bytesToFeed = 1024 * 1024 + 12345;
        rafDataSource.feed(0, bytesToFeed, dataSink);
        byte[] expectedBytes = Arrays.copyOf(fullFileContent, bytesToFeed);

        ByteBuffer result = dataSink.getByteBuffer(0, (int)dataSink.size());
        byte[] resultBytes = new byte[result.limit()];
        result.get(resultBytes);

        assertArrayEquals(expectedBytes, resultBytes);
    }
}
