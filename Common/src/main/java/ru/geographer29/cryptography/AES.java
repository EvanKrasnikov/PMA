package ru.geographer29.cryptography;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import static ru.geographer29.cryptography.LookupTables.*;

/**
 * @author Patrick Lu
 * @author Rishi Dewan
 */
public class AES {

    /**
     * S-BOX table used for Key Expansion and Sub-Bytes.
     */
    public static final String newline = System.getProperty("line.separator"); //The newline for whatever system you choose to run in.
    public static enum Mode { ECB,CBC };

    static String key = "";
    static String iv = "";
    static String ftw = "";
    static BufferedReader keyreader;
    static BufferedReader input;
    static Mode mode;
    static FileWriter out;
    static int keyFileIndex = 1; //Index where the keyFile argument should be. Used to determines the index of other arguments.

    /**
     * Main method with which we run the AES algorithm.
     * Usage: java AES e|d [-length] [-mode] keyFile inputFile
     * @param args Array of command line arguments.
     */
    public static void main(String args[]) throws IOException
    {
        /*
         * args[0] should be either "e" or "d"
         * args[1] and args[2] should correspond to the following:
         *
         * -length => "128" or "256"
         * -mode => "ecb" or "cbc"
         * neither -length nor -mode: args[1] should be the keyFile, and args[2] should be the inputFile
         *
         * args[3] and args[4] should exist only if -length was specified:
         */
        try
        {
            int keysizecheck = 128; //User's intended key size.
            if (!args[1].equals("-length")) //No optional length argument given.
            {
                if(!args[1].equals("-mode")) //No optional mode given either;
                {
                    //Defaults to 128-bit key size and ECB.
                }
                else //Mode option was given;
                {
                    mode = args[2].equals("ecb") ? Mode.ECB : Mode.CBC;
                    keyFileIndex += 2;
                }
            }
            else //-length was explicitly given.
            {
                keyFileIndex+=2;
                keysizecheck = Integer.parseInt(args[keyFileIndex-1]);
                if(args[3].equals("-mode")) //Both -length and -mode options were given
                {
                    mode = args[4].equals("ecb") ? Mode.ECB : Mode.CBC;
                    keyFileIndex+=2;
                }

            }
            keyreader = new BufferedReader(new FileReader(args[keyFileIndex]));
            key = keyreader.readLine();
            if(key.length() *4 != keysizecheck) //Check to see if user's intended key size matches the size of key in file.
            {
                throw new Exception("Error: Attemping to use a " + key.length() * 4 + "-bit key with AES-"+keysizecheck);
            }
            input = new BufferedReader(new FileReader(args[keyFileIndex+1]));
            if(mode == Mode.CBC)
            {
                iv = keyreader.readLine();
                if(iv == null)
                {
                    throw new Exception("Error: Initialization Vector required for CBC Mode.");
                }
                else if(iv.length() != 32)
                {
                    throw new Exception("Error: Size of Initialization Vector must be 32 bytes.");
                }
            }
            ftw += args[keyFileIndex+1];
        }
        catch (Exception e)
        {
            System.err.println(e.getMessage() + newline);
            System.exit(1);
        }

        AES aes = new AES();
        if (args[0].equalsIgnoreCase("e"))
        {
            out = new FileWriter(ftw + ".enc");
            int numRounds = 10 + (((key.length() * 4 - 128) / 32));
            String line = input.readLine();
            int[][] state, initvector = new int[4][4];
            int[][] keymatrix = aes.keySchedule(key);
            if(mode == Mode.CBC)
            {
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++) {
                        initvector[j][i] = Integer.parseInt(iv.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
                    }
                }
            }
            while (line != null) {
                if (line.matches("[0-9A-F]+")) //If line is valid (i.e. contains valid hex characters, encrpyt. Otherwise, skip line.
                {
                    if (line.length() < 32) {
                        line = String.format("%032x",Integer.parseInt(line, 16));
                    }
                    state = new int[4][4];
                    for (int i = 0; i < 4; i++) //Parses line into a matrix
                    {
                        for (int j = 0; j < 4; j++) {
                            state[j][i] = Integer.parseInt(line.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
                        }
                    }
                    if(mode == Mode.CBC)
                    {
                        aes.addRoundKey(state, initvector);
                    }
                    aes.addRoundKey(state, aes.subKey(keymatrix, 0)); //Starts the addRoundKey with the first part of Key Expansion
                    for (int i = 1; i < numRounds; i++) {
                        aes.subBytes(state); //implements the Sub-Bytes subroutine.
                        aes.shiftRows(state); //implements Shift-Rows subroutine.
                        aes.mixColumns(state);
                        aes.addRoundKey(state, aes.subKey(keymatrix, i));
                    }
                    aes.subBytes(state); //implements the Sub-Bytes subroutine.
                    aes.shiftRows(state); //implements Shift-Rows subroutine.
                    aes.addRoundKey(state, aes.subKey(keymatrix, numRounds));
                    if(mode == Mode.CBC)
                    {
                        initvector = state;
                    }
                    out.write(matrixToString(state) + newline); //If all systems could just use the same newline, I'd be set.
                    line = input.readLine();
                }
                else
                {
                    line = input.readLine();
                }
            }
            input.close();
            out.close();
        }
        else if (args[0].equalsIgnoreCase("d")) //Decryption Mode
        {
            out = new FileWriter(ftw + ".dec");
            int numRounds = 10 + (((key.length() * 4 - 128) / 32));
            String line = input.readLine();
            int[][] state = new int[4][4];
            int[][] initvector = new int[4][4];
            int[][] nextvector = new int[4][4];
            int[][] keymatrix = aes.keySchedule(key);
            if(mode == Mode.CBC) //Parse Initialization Vector
            {
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++) {
                        initvector[j][i] = Integer.parseInt(iv.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
                    }
                }
            }
            while (line != null) {
                state = new int[4][4];
                for (int i = 0; i < state.length; i++) //Parses line into a matrix
                {
                    for (int j = 0; j < state[0].length; j++) {
                        state[j][i] = Integer.parseInt(line.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
                    }
                }
                if(mode == Mode.CBC)
                {
                    aes.deepCopy2DArray(nextvector,state);
                }
                aes.addRoundKey(state, aes.subKey(keymatrix, numRounds));
                for (int i = numRounds - 1; i > 0; i--) {
                    aes.shiftRowsInv(state);
                    aes.invSubBytes(state);
                    aes.addRoundKey(state, aes.subKey(keymatrix, i));
                    aes.invMixColumns(state);
                }
                aes.shiftRowsInv(state);
                aes.invSubBytes(state);
                aes.addRoundKey(state, aes.subKey(keymatrix, 0));
                if(mode == Mode.CBC)
                {
                    aes.addRoundKey(state, initvector);
                    aes.deepCopy2DArray(initvector,nextvector);
                }
                out.write(matrixToString(state) + newline);
                line = input.readLine();
            }
            input.close();
            out.close();
        }
        else
        {
            System.err.println("Usage for Encryption: java AES e keyFile inputFile");
            System.err.println("Usage for Decryption: java AES d keyFile encryptedinputFile");
        }
    }

    //Helper method which executes a deep copy of a 2D array. (dest,src)
    private void deepCopy2DArray(int[][] destination, int[][] source) {
        assert destination.length == source.length && destination[0].length == source[0].length;
        for(int i = 0; i < destination.length;i++) {
            System.arraycopy(source[i], 0, destination[i], 0, destination[0].length);
        }
    }

    /**
     * Pulls out the subkey from the key formed from the keySchedule method
     * @param km key formed from AES.keySchedule()
     * @param begin index of where to fetch the subkey
     * @return The chunk of the scheduled key based on begin.
     */

    private int[][] subKey(int[][] km, int begin) {
        int[][] arr = new int[4][4];
        for (int i = 0; i < arr.length; i++) {
            for (int j = 0; j < arr.length; j++) {
                arr[i][j] = km[i][4 * begin + j];
            }
        }
        return arr;
    }

    /**
     * Replaces all elements in the passed array with values in sbox[][].
     * @param arr Array whose value will be replaced
     * @return The array who's value was replaced.
     */
    //Sub-Byte subroutine
    public void subBytes(int[][] arr) {
        for (int i = 0; i < arr.length; i++) {
            for (int j = 0; j < arr[0].length; j++) {
                int hex = arr[j][i];
                arr[j][i] = sbox[hex / 16][hex % 16];
            }
        }
    }

    /**
     * Inverse rendition of the subBytes. The operations of invSubBytes are the reverse operations of subBytes.
     * @param arr the array that is passed.
     */
    //Inverse Sub-Byte subroutine
    public void invSubBytes(int[][] arr) {
        for (int i = 0; i < arr.length; i++) {
            for (int j = 0; j < arr[0].length; j++) {
                int hex = arr[j][i];
                arr[j][i] = invsbox[hex / 16][hex % 16];
            }
        }
    }

    /**
     * Performs a left shift on each row of the matrix.
     * Left shifts the nth row n-1 times.
     * @param arr the reference of the array to perform the rotations.
     */

    public void shiftRows(int[][] arr) {
        for (int i = 1; i < arr.length; i++) {
            arr[i] = rotateLeft(arr[i], i);
        }
    }

    /**
     * Left rotates a given array. The size of the array is assumed to be 4.
     * If the number of times to rotate the array is divisible by 4, return the array
     * as it is.
     * @param arr The passed array (assumed to be of size 4)
     * @param times The number of times to rotate the array.
     * @return the rotated array.
     */

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

    /**
     * Inverse rendition of ShiftRows (this time, right rotations are used).
     * @param arr the array to compute right rotations.
     */

    public void shiftRowsInv(int[][] arr) {
        for (int i = 1; i < arr.length; i++) {
            arr[i] = rotateRight(arr[i], i);
        }
    }

    /**
     * Right reverses the array in a similar fashion as leftrotate
     * @param arr
     * @param times
     * @return
     */

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

    /**
     * Performed by mapping each element in the current matrix with the value
     * returned by its helper function.
     * @param arr the array with we calculate against the galois field matrix.
     */
    //method for mixColumns
    public void mixColumns(int[][] arr) {
        int[][] tarr = new int[4][4];
        for(int i = 0; i < 4; i++)
        {
            System.arraycopy(arr[i], 0, tarr[i], 0, 4);
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                arr[i][j] = mcHelper(tarr, galois, i, j);
            }
        }
    }

    /**
     * Helper method of mixColumns in which compute the mixColumn formula on each element.
     * @param arr passed in current matrix
     * @param g the galois field
     * @param i the row position
     * @param j the column position
     * @return the computed mixColumns value
     */

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

    public void invMixColumns(int[][] arr) {
        int[][] tarr = new int[4][4];
        for(int i = 0; i < 4; i++) {
            System.arraycopy(arr[i], 0, tarr[i], 0, 4);
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                arr[i][j] = invMcHelper(tarr, galoisInv, i, j);
            }
        }
    }

    //Helper method for invMixColumns
    private int invMcHelper(int[][] arr, int[][] igalois, int i, int j) {
        int mcsum = 0;
        for (int k = 0; k < 4; k++) {
            int a = igalois[i][k];
            int b = arr[k][j];
            mcsum ^= invMcCalc(a, b);
        }
        return mcsum;
    }

    /**
     * Helper computing method for inverted mixColumns.
     *
     * @param a Row Position of mcX.
     * @param b Column Position of mcX
     * @return the value in the corresponding mcX table based on the a,b coordinates.
     */
    //Helper method for invMcHelper
    private int invMcCalc(int a, int b) {
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

    /**
     *The keyScheduling algorithm to expand a short key into a number of separate round keys.
     *
     * @param key the key in which key expansion will be computed upon.
     * @return the fully computed expanded key for the AES encryption/decryption.
     */

    public int[][] keySchedule(String key) {
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
                t = schedule_core(t, rconpointer++);
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

    /**
     * For every (binary key size / 32)th column in the expanded key. We compute a special column
     * using sbox and an XOR of the an rcon number with the first element in the passed array.
     *
     * @param in the array in which we compute the next set of bytes for key expansion
     * @param rconpointer the element in the rcon array with which to XOR the first element in 'in'
     * @return the next column in the key scheduling.
     */

    public int[] schedule_core(int[] in, int rconpointer) {
        in = rotateLeft(in, 1);
        int hex;
        for (int i = 0; i < in.length; i++) {
            hex = in[i];
            in[i] = sbox[hex / 16][hex % 16];
        }
        in[0] ^= rcon[rconpointer];
        return in;
    }

    /**
     * In the AddRoundKey step, the subkey is combined with the state. For each round, a chunk of the key scheduled is pulled; each subkey is the same size as the state. Each element in the byte matrix is XOR'd with each element in the chunk of the expanded key.
     *
     * @param bytematrix reference of the matrix in which addRoundKey will be computed upon.
     * @param keymatrix chunk of the expanded key
     */

    public void addRoundKey(int[][] bytematrix, int[][] keymatrix) {
        for (int i = 0; i < bytematrix.length; i++) {
            for (int j = 0; j < bytematrix[0].length; j++) {
                bytematrix[j][i] ^= keymatrix[j][i];
            }
        }
    }

    /**
     * ToString() for the matrix (2D array).
     *
     * @param m reference of the matrix
     * @return the string representation of the matrix.
     */

    //takes in a matrix and converts it into a line of 32 hex characters.
    public static String matrixToString(int[][] m) {
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
}
