package ru.geographer29.cryptography;

import ru.geographer29.util.Util;
import java.security.SecureRandom;

import static ru.geographer29.cryptography.LookupTables.*;

public class AES {

    public enum Mode { ECB,CBC };
    private final Mode mode;

    public AES(Mode mode) {
        this.mode = mode;
    }

    public String encrypt16Bytes(String line, String iv, String key) {
        int numRounds = 10 + (((key.length() * 4 - 128) / 32));
        int[][] initVector = new int[4][4];
        int[][] state = new int[4][4];
        int[][] keyMatrix = keySchedule(key);

        if(mode == Mode.CBC) {
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    initVector[j][i] = Integer.parseInt(iv.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
                }
            }
        }

        //If line is valid (i.e. contains valid hex characters, encrpyt. Otherwise, skip line.
        if (line.length() < 32) {
            line = String.format("%032x", Integer.parseInt(line, 16));
        }

        //Parses line into a matrix
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = Integer.parseInt(line.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
            }
        }

        if (mode == Mode.CBC) {
            addRoundKey(state, initVector);
        }

        //Starts the addRoundKey with the first part of Key Expansion
        addRoundKey(state, subKey(keyMatrix, 0));

        for (int i = 1; i < numRounds; i++) {
            subBytes(state); //implements the Sub-Bytes subroutine.
            shiftRows(state); //implements Shift-Rows subroutine.
            mixColumns(state);
            addRoundKey(state, subKey(keyMatrix, i));
        }
        subBytes(state); //implements the Sub-Bytes subroutine.
        shiftRows(state); //implements Shift-Rows subroutine.
        addRoundKey(state, subKey(keyMatrix, numRounds));

        if (mode == Mode.CBC) {
            initVector = state;
        }

        // return matrixToString(state) + newLine;
        return matrixToString(state);
    }

    public String encrypt(String line, String iv, String key){
        String result;


        System.out.println("Before = " + line);
        line = Util.bytesToHex(line.getBytes());
        System.out.println("After = " + line);
        int len = line.length();

        if (len % 32 != 0) {
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < 32 - (len % 32); i++) {
                sb.append('0');
            }

            line += sb.toString();
            System.out.println("Msg len = " + len);
            System.out.println("Add len = " + (32 - (len % 32)));
            System.out.println("Combined = " + line);
            System.out.println("Msg len = " + line.length());
        }

        if (line.length() > 32){
            StringBuilder sb = new StringBuilder();
            int begin = 0;
            int end = 32;

            while (end <= line.length()){
                if (end > line.length()){
                    end = line.length();
                }
                String nextChunk = line.substring(begin, end);
                System.out.println("Chunk = " + nextChunk);
                System.out.println("Chunk len = " + end);
                String encrypted = encrypt16Bytes(nextChunk, iv, key);
                sb.append(encrypted);
                begin += 32;
                end += 32;
            }

            result = sb.toString();
        } else {
            result = encrypt16Bytes(line, iv, key);
        }
        System.out.println(result);
        return result;
    }

    public String decrypt16Bytes(String line, String iv, String key) {
        int numRounds = 10 + (((key.length() * 4 - 128) / 32));
        int[][] state = new int[4][4];
        int[][] initVector = new int[4][4];
        int[][] nextVector = new int[4][4];
        int[][] keyMatrix = keySchedule(key);

        //Parse Initialization Vector
        if(mode == Mode.CBC) {
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    initVector[j][i] = Integer.parseInt(iv.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
                }
            }
        }

        //Parses line into a matrix
        for (int i = 0; i < state.length; i++) {
            for (int j = 0; j < state[0].length; j++) {
                state[j][i] = Integer.parseInt(line.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
            }
        }

        if(mode == Mode.CBC) {
            deepCopy2DArray(nextVector,state);
        }

        addRoundKey(state, subKey(keyMatrix, numRounds));
        for (int i = numRounds - 1; i > 0; i--) {
            shiftRowsInv(state);
            subBytesInv(state);
            addRoundKey(state, subKey(keyMatrix, i));
            mixColumnsInv(state);
        }

        shiftRowsInv(state);
        subBytesInv(state);
        addRoundKey(state, subKey(keyMatrix, 0));

        if(mode == Mode.CBC) {
            addRoundKey(state, initVector);
            deepCopy2DArray(initVector,nextVector);
        }

        return matrixToString(state);
    }

    public String decrypt(String line, String iv, String key) {
        String result;

        if (line.length() > 32){
            StringBuilder sb = new StringBuilder();
            int begin = 0;
            int end = 32;

            while (end <= line.length()){
                String nextChunk = line.substring(begin, end);
                String decrypted = decrypt16Bytes(nextChunk, iv, key);
                sb.append(decrypted);
                begin += 32;
                end += 32;
            }

            result = sb.toString();
        } else {
            result = encrypt16Bytes(line, iv, key);
        }
        return new String(Util.hexToBytes(result));
    }

    //Helper method which executes a deep copy of a 2D array. (dest,src)
    private void deepCopy2DArray(int[][] destination, int[][] source) {
        assert destination.length == source.length && destination[0].length == source[0].length;
        for(int i = 0; i < destination.length;i++) {
            System.arraycopy(source[i], 0, destination[i], 0, destination[0].length);
        }
    }

    // Pulls out the subkey from the key formed from the keySchedule method
    private int[][] subKey(int[][] km, int begin) {
        int[][] arr = new int[4][4];
        for (int i = 0; i < arr.length; i++) {
            for (int j = 0; j < arr.length; j++) {
                arr[i][j] = km[i][4 * begin + j];
            }
        }
        return arr;
    }

    // Replaces all elements in the passed array with values in sbox[][].
    private void subBytes(int[][] arr) {
        for (int i = 0; i < arr.length; i++) {
            for (int j = 0; j < arr[0].length; j++) {
                int hex = arr[j][i];
                arr[j][i] = sbox[hex / 16][hex % 16];
            }
        }
    }

    // Inverse rendition of the subBytes. The operations of invSubBytes are the reverse operations of subBytes.
    private void subBytesInv(int[][] arr) {
        for (int i = 0; i < arr.length; i++) {
            for (int j = 0; j < arr[0].length; j++) {
                int hex = arr[j][i];
                arr[j][i] = invsbox[hex / 16][hex % 16];
            }
        }
    }

    // Performs a left shift on each row of the matrix.
    private void shiftRows(int[][] arr) {
        for (int i = 1; i < arr.length; i++) {
            arr[i] = rotateLeft(arr[i], i);
        }
    }

    //Left rotates a given array. The size of the array is assumed to be 4.
    //If the number of times to rotate the array is divisible by 4, return the array as it is.
    private int[] rotateLeft(int[] arr, int times) {
        assert(arr.length == 4);
        if (times % 4 == 0) {
            return arr;
        }
        while (times > 0) {
            int temp = arr[0];
            for (int i = 0; i < arr.length - 1; i++) {
                arr[i] = arr[i + 1];
            }
            arr[arr.length - 1] = temp;
            --times;
        }
        return arr;
    }

    // Inverse rendition of ShiftRows (this time, right rotations are used)
    private void shiftRowsInv(int[][] arr) {
        for (int i = 1; i < arr.length; i++) {
            arr[i] = rotateRight(arr[i], i);
        }
    }

    // Right reverses the array in a similar fashion as leftrotate
    private int[] rotateRight(int[] arr, int times) {
        if (arr.length == 0 || arr.length == 1 || times % 4 == 0) {
            return arr;
        }
        while (times > 0) {
            int temp = arr[arr.length - 1];
            for (int i = arr.length - 1; i > 0; i--) {
                arr[i] = arr[i - 1];
            }
            arr[0] = temp;
            --times;
        }
        return arr;
    }

    // Performed by mapping each element in the current matrix with the value returned by its helper function.
    private void mixColumns(int[][] arr) {
        int[][] tarr = new int[4][4];
        for(int i = 0; i < 4; i++) {
            System.arraycopy(arr[i], 0, tarr[i], 0, 4);
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                arr[i][j] = mcHelper(tarr, galois, i, j);
            }
        }
    }

    // Helper method of mixColumns in which compute the mixColumn formula on each element
    private int mcHelper(int[][] arr, int[][] g, int i, int j) {
        int mcsum = 0;
        for (int k = 0; k < 4; k++) {
            int a = g[i][k];
            int b = arr[k][j];
            mcsum ^= mcCalc(a, b);
        }
        return mcsum;
    }

    //Helper method for mcHelper
    private int mcCalc(int a, int b) {
        if (a == 1) {
            return b;
        } else if (a == 2) {
            return LookupTables.mc2[b / 16][b % 16];
        } else if (a == 3) {
            return LookupTables.mc3[b / 16][b % 16];
        }
        return 0;
    }

    private void mixColumnsInv(int[][] arr) {
        int[][] tarr = new int[4][4];
        for(int i = 0; i < 4; i++) {
            System.arraycopy(arr[i], 0, tarr[i], 0, 4);
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                arr[i][j] = mcHelperInv(tarr, galoisInv, i, j);
            }
        }
    }

    //Helper method for invMixColumns
    private int mcHelperInv(int[][] arr, int[][] igalois, int i, int j) {
        int mcsum = 0;
        for (int k = 0; k < 4; k++) {
            int a = igalois[i][k];
            int b = arr[k][j];
            mcsum ^= mcCalcInv(a, b);
        }
        return mcsum;
    }

    //Helper computing method for inverted mixColumns
    private int mcCalcInv(int a, int b) {
        if (a == 9) {
            return LookupTables.mc9[b / 16][b % 16];
        } else if (a == 0xb) {
            return LookupTables.mc11[b / 16][b % 16];
        } else if (a == 0xd) {
            return LookupTables.mc13[b / 16][b % 16];
        } else if (a == 0xe) {
            return LookupTables.mc14[b / 16][b % 16];
        }
        return 0;
    }

    // The keyScheduling algorithm to expand a short key into a number of separate round keys
    private int[][] keySchedule(String key) {
        int binkeysize = key.length() * 4;
        int colsize = binkeysize + 48 - (32 * ((binkeysize / 64) - 2)); //size of key scheduling will be based on the binary size of the key.
        int[][] keyMatrix = new int[4][colsize / 4]; //creates the matrix for key scheduling
        int rconpointer = 1;
        int[] t = new int[4];
        final int keycounter = binkeysize / 32;
        int k;

        for (int i = 0; i < keycounter; i++) //the first 1 (128-bit key) or 2 (256-bit key) set(s) of 4x4 matrices are filled with the key.
        {
            for (int j = 0; j < 4; j++) {
                keyMatrix[j][i] = Integer.parseInt(key.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
            }
        }
        int keypoint = keycounter;
        while (keypoint < (colsize / 4)) {
            int temp = keypoint % keycounter;
            if (temp == 0) {
                for (k = 0; k < 4; k++) {
                    t[k] = keyMatrix[k][keypoint - 1];
                }
                t = scheduleCore(t, rconpointer++);
                for (k = 0; k < 4; k++) {
                    keyMatrix[k][keypoint] = t[k] ^ keyMatrix[k][keypoint - keycounter];
                }
                keypoint++;
            } else if (temp == 4) {
                for (k = 0; k < 4; k++) {
                    int hex = keyMatrix[k][keypoint - 1];
                    keyMatrix[k][keypoint] = sbox[hex / 16][hex % 16] ^ keyMatrix[k][keypoint - keycounter];
                }
                keypoint++;
            } else {
                int ktemp = keypoint + 3;
                while (keypoint < ktemp) {
                    for (k = 0; k < 4; k++) {
                        keyMatrix[k][keypoint] = keyMatrix[k][keypoint - 1] ^ keyMatrix[k][keypoint - keycounter];
                    }
                    keypoint++;
                }
            }
        }
        return keyMatrix;
    }

    // For every (binary key size / 32)th column in the expanded key. We compute a special column
    // using sbox and an XOR of the an rcon number with the first element in the passed array.
    private int[] scheduleCore(int[] in, int rconpointer) {
        in = rotateLeft(in, 1);
        int hex;
        for (int i = 0; i < in.length; i++) {
            hex = in[i];
            in[i] = sbox[hex / 16][hex % 16];
        }
        in[0] ^= rcon[rconpointer];
        return in;
    }

    //  In the AddRoundKey step, the subkey is combined with the state.
    //  For each round, a chunk of the key scheduled is pulled; each subkey is the same size as the state.
    //  Each element in the byte matrix is XOR'd with each element in the chunk of the expanded key.
    private void addRoundKey(int[][] bytematrix, int[][] keymatrix) {
        for (int i = 0; i < bytematrix.length; i++) {
            for (int j = 0; j < bytematrix[0].length; j++) {
                bytematrix[j][i] ^= keymatrix[j][i];
            }
        }
    }

    //takes in a matrix and converts it into a line of 32 hex characters.
    private static String matrixToString(int[][] m) {
        String t = "";
        for (int i = 0; i < m.length; i++) {
            for (int j = 0; j < m[0].length; j++) {
                String h = Integer.toHexString(m[j][i]).toUpperCase();
                if (h.length() == 1) {
                    t += '0' + h;
                } else {
                    t += h;
                }
            }
        }
        return t;
    }

    // default - 128 bits
    public static String generateSecretKey(int keyLength) {
        keyLength /= 4;
        SecureRandom r = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        while(sb.length() < keyLength){
            sb.append(Integer.toHexString(r.nextInt()));
        }
        return sb.toString().trim().toUpperCase();
    }

}
