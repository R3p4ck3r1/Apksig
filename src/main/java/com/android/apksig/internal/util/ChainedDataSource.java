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
import com.android.apksig.util.ReadableDataSink;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/** A pseudo {@link DataSource} that chains the given {@Link DataSource} as a continuous one. */
public class ChainedDataSource implements DataSource {

    private final DataSource[] mSources;
    private final long mTotalSize;

    public ChainedDataSource(DataSource... sources) {
        mSources = sources;
        mTotalSize =
        Arrays.stream(sources).mapToLong(src -> src.size()).sum();
    }

    @Override
    public long size() {
        return mTotalSize;
    }

    @Override
    public void feed(long offset, long size, DataSink sink) throws IOException {
        if (offset + size > mTotalSize) {
            throw new IndexOutOfBoundsException("Requested more than available");
        }

        ByteBuffer buffer = null;
        for (DataSource src : mSources) {
            // Offset is beyond the current source. Skip.
            if (offset >= src.size()) {
                offset -= src.size();
                continue;
            }

            // If the remaining is enough, finish it.
            long remaining = src.size() - offset;
            if (remaining >= size) {
                // If something has been readed before, read the remaining data into the buffer,
                // then feed them at once.
                if (buffer != null) {
                    if (offset != 0) {
                        throw new IllegalStateException("Cannot skip continuous data");
                    }
                    src.copyTo(offset, Math.toIntExact(size), buffer);
                    break;
                }

                // If everything is within the current source, just consume the slice.
                sink.consume(src.getByteBuffer(offset, Math.toIntExact(size)));
                return;
            }

            // If we need more than the current remaining, accumulate in a buffer so that we can
            // still feed the sink at once.
            if (buffer == null) {
                buffer = ByteBuffer.allocate(Math.toIntExact(size));
            }
            src.copyTo(offset, Math.toIntExact(remaining), buffer);
            size -= remaining;
            offset = 0;
        }

        if (buffer != null) {
            buffer.rewind();
            sink.consume(buffer);
        }
    }

    @Override
    public ByteBuffer getByteBuffer(long offset, int size) throws IOException {
        if (offset + size > mTotalSize) {
            throw new IndexOutOfBoundsException("Requested more than available");
        }
        ReadableDataSink sink = DataSinks.newInMemoryDataSink(size);
        feed(offset, size, sink);
        return sink.getByteBuffer(0, size);
    }

    @Override
    public void copyTo(long offset, int size, ByteBuffer dest) throws IOException {
        feed(offset, size, new ByteBufferSink(dest));
    }

    @Override
    public DataSource slice(long offset, long size) {
        throw new UnsupportedOperationException("Not implemented");
    }
}
