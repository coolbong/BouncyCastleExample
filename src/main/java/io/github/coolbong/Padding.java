package io.github.coolbong;

import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;

import java.util.Arrays;

public class Padding {

    public byte[] zeroPadding(byte[] input, int blockSize) {

        int length = blockSize - (input.length % blockSize);

        byte[] padded = Arrays.copyOf(input, input.length + length);

        BlockCipherPadding padding = new ZeroBytePadding();
        padding.init(null);
        //padding.addPadding(padded, )

        //padding.addPadding(input, )
        int ret = getOutputSize(16);
        System.out.println(ret);

        return null;
    }

    public int getOutputSize(int len) {
        int total       = len;
        int leftOver    = total % 16;

        if (leftOver == 0) {
            return total + 16;
        }

        return total - leftOver + 16;
    }

    public static void main(String[] args) {
        Padding padding = new Padding();
        byte[] ret = padding.zeroPadding(new byte[10], 16);
    }
}
