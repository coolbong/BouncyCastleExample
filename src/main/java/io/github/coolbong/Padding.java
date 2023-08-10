package io.github.coolbong;

import org.bouncycastle.crypto.paddings.*;

import java.util.Arrays;

public class Padding {

    public byte[] zeroPadding(byte[] input, int blockSize) {

        int length = blockSize - (input.length % blockSize);
        byte[] padded = Arrays.copyOf(input, input.length + length);

        BlockCipherPadding padding = new ZeroBytePadding();
        padding.init(null);
        padding.addPadding(padded, input.length);
        return padded;
    }

    public byte[] desPadding(byte[] input, int blockSize) {
        int length = blockSize - (input.length % blockSize);
        byte[] padded = Arrays.copyOf(input, input.length + length);

        BlockCipherPadding padding = new ISO7816d4Padding();
        padding.init(null);
        padding.addPadding(padded, input.length);
        return padded;
    }

    public byte[] is1026dPadding(byte[] input, int blockSize) {
        int length = blockSize - (input.length % blockSize);
        byte[] padded = Arrays.copyOf(input, input.length + length);

        BlockCipherPadding padding = new ISO10126d2Padding();
        padding.init(null);
        padding.addPadding(padded, input.length);
        return padded;
    }

    public byte[] tbcPadding(byte[] input, int blockSize) {
        int length = blockSize - (input.length % blockSize);
        byte[] padded = Arrays.copyOf(input, input.length + length);

        BlockCipherPadding padding = new TBCPadding();
        padding.init(null);
        padding.addPadding(padded, input.length);
        return padded;
    }

    public byte[] x923Padding(byte[] input, int blockSize) {
        int length = blockSize - (input.length % blockSize);
        byte[] padded = Arrays.copyOf(input, input.length + length);

        BlockCipherPadding padding = new X923Padding();
        padding.init(null);
        padding.addPadding(padded, input.length);
        return padded;
    }

    public byte[] pkcs7Padding(byte[] input, int blockSize) {
        int length = blockSize - (input.length % blockSize);
        byte[] padded = Arrays.copyOf(input, input.length + length);

        BlockCipherPadding padding = new PKCS7Padding();
        padding.init(null);
        padding.addPadding(padded, input.length);
        return padded;
    }

}
