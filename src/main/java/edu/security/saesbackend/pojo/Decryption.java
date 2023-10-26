package edu.security.saesbackend.pojo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import service.AesService;

import java.awt.*;
import java.util.Arrays;
@Service
@Slf4j
public class Decryption {
    static int[][]sBox=new int[][]{{0xA,0x5,0x9,0xB},{0x1,0x7,0x8,0xF},{0x6,0x0,0x2,0x3},{0xC,0x4,0xD,0xE}};
    static int[][]sBoxKey=new int[][]{{0x9,0x4,0xA,0xB},{0xD,0x1,0x8,0x5},{0x6,0x2,0x0,0x3},{0xC,0xE,0xF,0x7}};
    String key0;
    String key1;
    int[] key0Array;
    int[] key1Array;
    int[] key2Array;
    int[] key3Array;
    int[] key4Array;
    int[] key5Array;
    int[] subKey0 = new int[16];
    int[] subKey1 = new int[16];
    int[] subKey2 = new int[16];
    static int[][] GFPlus = new int[16][16];
    static int A=0xA;
    static int B=0xB;
    static int C=0xC;
    static int D=0xD;
    static int E=0xE;
    static int F=0xF;
    static int[][] GFProduct = {
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {0, 2, 4, 6, 8, A, C, E, 3, 1, 7, 5, B, 9, F, D},
            {0, 3, 6, 5, C, 15, 10, 9, B, 8, D, E, 7, 4, 1, 2},
            {0, 4, 8, C, 3, 7, 11, 15, 6, 2, E, 10, 5, 1, D, 9},
            {0, 5, 10, 15, 7, 2, D, 8, E, B, 4, 1, 9, C, 3, 6},
            {0, 6, C, A, B, D, 7, 1, 5, 3, 9, F, E, 8, 2, 4},
            {0, 7, E, 9, F, 8, 1, 6, D, A, 3, 4, 2, 5, C, B},
            {0, 8, 3, B, 6, E, 5, D, C, 4, F, 7, A, 2, 9, 1},
            {0, 9, 1, 8, 2, B, 3, A, 4, D, 5, C, 6, F, 7, E},
            {0, A, 7, D, E, 4, 9, 3, F, 5, 8, 2, 1, B, 6, C},
            {0, B, 5, E, A, 1, F, 4, 7, C, 2, 9, D, 6, 8, 3},
            {0, C, B, 7, 5, 9, E, 2, A, 6, 1, D, F, 3, 4, 8},
            {0, D, 9, 4, 1, C, 8, 5, 2, F, B, 6, 3, E, A, 7},
            {0, E, F, 1, D, 3, 2, C, 9, 7, 6, 8, 4, A, B, 5},
            {0, 15, 13, 2, 9, 6, 4, B, 1, E, C, 3, 8, 7, 5, A}
    };



    static {
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 16; j++) {
                GFPlus[i][j] = i ^ j;
            }
        }
    }



    public void setKey0(String key0){
        this.key0=key0;
    }
    public void setKey1(String key1){
        this.key1=key1;
    }
    public static int[] RotNib(int[] inputArray) {
        if (inputArray.length != 8) {
            throw new IllegalArgumentException("Input array must be of length 8");
        }
        int[] rotatedArray = new int[8];

        // Swap the first 4 elements with the last 4 elements
        for (int i = 0; i < 8; i++) {
            if (i < 4) {
                rotatedArray[i] = inputArray[i + 4];
            } else {
                rotatedArray[i] = inputArray[i - 4];
            }
        }
        return rotatedArray;
    }
    public int[] getKey0Array(){
        return this.key0Array;
    }
    public int[] getKey4Array(){
        return this.key4Array;
    }
    public int[] getKey1Array() {
        return this.key1Array;
    }
    public int[] getKey2Array() {
        return this.key2Array;
    }
    public int[] getKey3Array(){
        return this.key3Array;
    }
    public int[] getKey5Array(){
        return this.key5Array;
    }
    public static int[] XOR(int[] array1, int[] array2) {
        if (array1.length != array2.length) {
            throw new IllegalArgumentException("Input arrays must be of the same length");
        }
        int[] result = new int[array1.length];

        for (int i = 0; i < array1.length; i++) {
            result[i] = array1[i] ^ array2[i];
        }
        return result;
    }
    // Helper function to convert a binary array to a decimal value
    public static int binaryToDecimal(int[] binaryArray) {
        int decimalValue = 0;
        for (int i = 0; i < binaryArray.length; i++) {
            decimalValue = decimalValue * 2 + binaryArray[i];
        }
        return decimalValue;
    }

    // Helper function to convert a decimal value to a binary array
    public static int[] decimalToBinary(int decimalValue) {
        int[] binaryArray = new int[4];
        for (int i = 3; i >= 0; i--) {
            binaryArray[i] = decimalValue % 2;
            decimalValue /= 2;
        }
        return binaryArray;
    }
    public static int[] SubNib(int[] inputArray) {
        if (inputArray.length != 8) {
            throw new IllegalArgumentException("Input array must be of length 8");
        }

        // Divide the input into two 4-bit nibbles
        int[] nibble1 = Arrays.copyOfRange(inputArray, 0, 4);
        int[] nibble2 = Arrays.copyOfRange(inputArray, 4, 8);

        // Convert each nibble to decimal values for rows and columns
        int row1 = binaryToDecimal(Arrays.copyOfRange(nibble1, 0, 2));
        int col1 = binaryToDecimal(Arrays.copyOfRange(nibble1, 2, 4));

        int row2 = binaryToDecimal(Arrays.copyOfRange(nibble2, 0, 2));
        int col2 = binaryToDecimal(Arrays.copyOfRange(nibble2, 2, 4));

        // Look up the values in the S-Box
        int substitutedValue1 = sBoxKey[row1][col1];
        int substitutedValue2 = sBoxKey[row2][col2];

        // Convert the substituted values back to binary (4-bit)
        int[] substitutedNibble1 = decimalToBinary(substitutedValue1);
        int[] substitutedNibble2 = decimalToBinary(substitutedValue2);

        // Combine the two substituted nibbles into an 8-bit array
        int[] substitutedArray = new int[8];
        System.arraycopy(substitutedNibble1, 0, substitutedArray, 0, 4);
        System.arraycopy(substitutedNibble2, 0, substitutedArray, 4, 4);
        return substitutedArray;
    }
    public int[] round1(int[] plainTextArray){

//        Inverse Shift Row (same as normal)

        int[] rowShiftedArray= new int[16];
        for(int i=0;i<16;i++){
            if(i>=3&&i<=7){
                rowShiftedArray[i]=plainTextArray[i+8];
            }else if(i>=11&&i<=15){
                rowShiftedArray[i]=plainTextArray[i-8];
            }else{
                rowShiftedArray[i]=plainTextArray[i];
            }
        }
        //log.info("shift rows {}",AesService.BinaryToString(rowShiftedArray));

        //        Inverse Nibble Sub (use the inverse or decryption S-box)
        int[] nibble1_round1 = Arrays.copyOfRange(rowShiftedArray, 0, 4);
        int[] nibble2_round1 = Arrays.copyOfRange(rowShiftedArray, 4, 8);
        int[] nibble3_round1 = Arrays.copyOfRange(rowShiftedArray, 8, 12);
        int[] nibble4_round1 = Arrays.copyOfRange(rowShiftedArray, 12, 16);

        int row1 = binaryToDecimal(Arrays.copyOfRange(nibble1_round1, 0, 2));
        int col1 = binaryToDecimal(Arrays.copyOfRange(nibble1_round1, 2, 4));

        int row2 = binaryToDecimal(Arrays.copyOfRange(nibble2_round1, 0, 2));
        int col2 = binaryToDecimal(Arrays.copyOfRange(nibble2_round1, 2, 4));

        int row3 = binaryToDecimal(Arrays.copyOfRange(nibble3_round1, 0, 2));
        int col3 = binaryToDecimal(Arrays.copyOfRange(nibble3_round1, 2, 4));

        int row4 = binaryToDecimal(Arrays.copyOfRange(nibble4_round1, 0, 2));
        int col4 = binaryToDecimal(Arrays.copyOfRange(nibble4_round1, 2, 4));

        int substitutedValue1 = sBox[row1][col1];
        int substitutedValue2 = sBox[row2][col2];
        int substitutedValue3 = sBox[row3][col3];
        int substitutedValue4 = sBox[row4][col4];

        // Convert the substituted values back to binary (4-bit)
        int[] substitutedNibble1 = decimalToBinary(substitutedValue1);
        int[] substitutedNibble2 = decimalToBinary(substitutedValue2);
        int[] substitutedNibble3 = decimalToBinary(substitutedValue3);
        int[] substitutedNibble4 = decimalToBinary(substitutedValue4);


        int[] substitutedArray = new int[16];
        System.arraycopy(substitutedNibble1, 0, substitutedArray, 0, 4);
        System.arraycopy(substitutedNibble2, 0, substitutedArray, 4, 4);
        System.arraycopy(substitutedNibble3, 0, substitutedArray, 8, 4);
        System.arraycopy(substitutedNibble4, 0, substitutedArray, 12, 4);
        //log.info("inverse Sbox {}", AesService.BinaryToString(substitutedArray));
        //        Add Round 1 Key
        int[] plusArray=XOR(substitutedArray,subKey1);

        //log.info("add round 1 key {}",AesService.BinaryToString(plusArray));

        int[] nibble1 = Arrays.copyOfRange(plusArray, 0, 4);
        int[] nibble2 = Arrays.copyOfRange(plusArray, 4, 8);
        int[] nibble3 = Arrays.copyOfRange(plusArray, 8, 12);
        int[] nibble4 = Arrays.copyOfRange(plusArray, 12, 16);
        //log.info("Nibble1 is {}",nibble1);
        //log.info("Nibble2 is {}",nibble2);
        //log.info("Nibble3 is {}",nibble3);
        //log.info("Nibble4 is {}",nibble4);
        int[] newNibble1=XOR(decimalToBinary(GFProduct[9][binaryToDecimal(nibble1)]),decimalToBinary(GFProduct[2][binaryToDecimal(nibble2)]));
        int[] newNibble2=XOR(decimalToBinary(GFProduct[9][binaryToDecimal(nibble2)]),decimalToBinary(GFProduct[2][binaryToDecimal(nibble1)]));
        int[] newNibble3=XOR(decimalToBinary(GFProduct[2][binaryToDecimal(nibble4)]),decimalToBinary(GFProduct[9][binaryToDecimal(nibble3)]));
        int[] newNibble4=XOR(decimalToBinary(GFProduct[2][binaryToDecimal(nibble3)]),decimalToBinary(GFProduct[9][binaryToDecimal(nibble4)]));
        //log.info("new Nibble00 is {}",newNibble1);
        //log.info("new Nibble01 is {}",newNibble2);
        //log.info("new Nibble10 is {}",newNibble3);
        //log.info("new Nibble11 is {}",newNibble4);
        int[]  mixColArray =new int[16];
        System.arraycopy(newNibble1, 0, mixColArray, 0, 4);
        System.arraycopy(newNibble2, 0, mixColArray, 4, 4);
        System.arraycopy(newNibble3, 0, mixColArray, 8, 4);
        System.arraycopy(newNibble4, 0, mixColArray, 12, 4);
        //log.info("Mixcol {}",AesService.BinaryToString(mixColArray));
        return round2(mixColArray);
    }
    public int[] round2(int[] plainTextArray){

        int[] rowShiftedArray= new int[16];
        for(int i=0;i<16;i++){
            if(i>=3&&i<=7){
                rowShiftedArray[i]=plainTextArray[i+8];
            }else if(i>=11&&i<=15){
                rowShiftedArray[i]=plainTextArray[i-8];
            }else{
                rowShiftedArray[i]=plainTextArray[i];
            }
        }
        //log.info("shitf rows {}",AesService.BinaryToString(rowShiftedArray));


        //        Inverse Nibble Sub (use the inverse or decryption S-box)
        int[] nibble1_round1 = Arrays.copyOfRange(rowShiftedArray, 0, 4);
        int[] nibble2_round1 = Arrays.copyOfRange(rowShiftedArray, 4, 8);
        int[] nibble3_round1 = Arrays.copyOfRange(rowShiftedArray, 8, 12);
        int[] nibble4_round1 = Arrays.copyOfRange(rowShiftedArray, 12, 16);

        int row1 = binaryToDecimal(Arrays.copyOfRange(nibble1_round1, 0, 2));
        int col1 = binaryToDecimal(Arrays.copyOfRange(nibble1_round1, 2, 4));

        int row2 = binaryToDecimal(Arrays.copyOfRange(nibble2_round1, 0, 2));
        int col2 = binaryToDecimal(Arrays.copyOfRange(nibble2_round1, 2, 4));

        int row3 = binaryToDecimal(Arrays.copyOfRange(nibble3_round1, 0, 2));
        int col3 = binaryToDecimal(Arrays.copyOfRange(nibble3_round1, 2, 4));

        int row4 = binaryToDecimal(Arrays.copyOfRange(nibble4_round1, 0, 2));
        int col4 = binaryToDecimal(Arrays.copyOfRange(nibble4_round1, 2, 4));

        int substitutedValue1 = sBox[row1][col1];
        int substitutedValue2 = sBox[row2][col2];
        int substitutedValue3 = sBox[row3][col3];
        int substitutedValue4 = sBox[row4][col4];

        // Convert the substituted values back to binary (4-bit)
        int[] substitutedNibble1 = decimalToBinary(substitutedValue1);
        int[] substitutedNibble2 = decimalToBinary(substitutedValue2);
        int[] substitutedNibble3 = decimalToBinary(substitutedValue3);
        int[] substitutedNibble4 = decimalToBinary(substitutedValue4);

        int[] substitutedArray = new int[16];
        System.arraycopy(substitutedNibble1, 0, substitutedArray, 0, 4);
        System.arraycopy(substitutedNibble2, 0, substitutedArray, 4, 4);
        System.arraycopy(substitutedNibble3, 0, substitutedArray, 8, 4);
        System.arraycopy(substitutedNibble4, 0, substitutedArray, 12, 4);


        //log.info("inverse sbox {}",AesService.BinaryToString(substitutedArray));
        int[] plusArray=XOR(substitutedArray,subKey0);
        //log.info("add round 0 key {}",AesService.BinaryToString(plusArray));
        return plusArray;
    }

    public int[] decrypt(Object plainText) {
        int[] plainTextArray=new int[16];
        if (plainText instanceof Character) {
            plainTextArray=decryptChar((char) plainText);
        } else if (plainText instanceof String) {
            plainTextArray=decryptString((String) plainText);
        }

        this.key0Array=new int[8];
        this.key1Array=new int[8];
        this.key2Array=new int[8];
        this.key3Array=new int[8];
        this.key4Array=new int[8];
        this.key5Array=new int[8];
        for (int i = 0; i < 8; i++) {
            key0Array[i] = Integer.parseInt(this.key0.substring(i, i + 1));
            key1Array[i] = Integer.parseInt(this.key1.substring(i, i + 1));
        }

        key2Array=XOR(key0Array,XOR(new int[]{1,0,0,0,0,0,0,0},SubNib(RotNib(key1Array))));
        key3Array=XOR(key2Array,key1Array);
        key4Array=XOR(key2Array,XOR(new int[]{0,0,1,1,0,0,0,0},SubNib(RotNib(key3Array))));
        key5Array=XOR(key4Array,key3Array);
        System.arraycopy(key0Array, 0, subKey0, 0, 8);
        System.arraycopy(key1Array, 0, subKey0, 8, 8);
        System.arraycopy(key2Array, 0, subKey1, 0, 8);
        System.arraycopy(key3Array, 0, subKey1, 8, 8);
        System.arraycopy(key4Array, 0, subKey2, 0, 8);
        System.arraycopy(key5Array, 0, subKey2, 8, 8);
        //log.info("key0 is {}",subKey0);
        //log.info("key1 is {}",subKey1);
        //log.info("key2 is {}",subKey2);
        //log.info("ori is {}",AesService.BinaryToString(plainTextArray));
//        Add round 2 key
        plainTextArray=XOR(plainTextArray,subKey2);
        //log.info("add round 2 key {}",AesService.BinaryToString(plainTextArray));
//        round 1
        return round1(plainTextArray);
    }

    public static int[] decryptChar(char plainText) {
        String binaryText = String.format("%16s", Integer.toBinaryString(plainText)).replace(' ', '0');
        int[] binaryArray = new int[16];
        for (int i = 0; i < 16; i++) {
            binaryArray[i] = binaryText.charAt(i) - '0';
        }
        return binaryArray;
    }

    public static int[] decryptString(String binaryText) {
        int[] binaryArray = new int[16];
        for (int i = 0; i < 16; i++) {
            binaryArray[i] = binaryText.charAt(i) - '0';
        }
        return binaryArray;
    }
}
