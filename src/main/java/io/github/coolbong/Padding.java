package io.github.coolbong;

import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;

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

    public byte[] pkcs7Padding(byte[] input, int blockSize) {
        int length = blockSize - (input.length % blockSize);
        byte[] padded = Arrays.copyOf(input, input.length + length);

        BlockCipherPadding padding = new PKCS7Padding();
        padding.init(null);
        padding.addPadding(padded, input.length);
        return padded;
    }

    public static void main(String[] args) {
        Padding padding = new Padding();

        byte[] ret = padding.zeroPadding(new byte[10], 16);
    }
}
