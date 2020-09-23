package com.android.merklegen;

import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import com.android.apksig.internal.util.FileChannelDataSource;
import com.android.apksig.internal.util.VerityTreeBuilder;
import com.android.apksig.util.DataSource;

final class MerkleGen {

  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
        System.out.println("Expect 2 args: input output");
        return;
    }
    String filename = args[0];
    String treeFilename = args[1];

    try (RandomAccessFile raf = new RandomAccessFile(filename, "r");
        FileOutputStream outStream = new FileOutputStream(treeFilename);
        VerityTreeBuilder builder = new VerityTreeBuilder(null)) {

        DataSource dataSource = new FileChannelDataSource(raf.getChannel());

        ByteBuffer tree = builder.generateVerityTree(dataSource);
        System.out.println("Merkle tree size: " + tree.limit());

        int written = 0;
        while (written < tree.limit()) {
            written += outStream.getChannel().write(tree);
        }
    }
  }
}
