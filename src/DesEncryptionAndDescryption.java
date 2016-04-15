import java.util.HashMap;
import java.util.Map;

/**
 * Created by ljkey on 2016/3/29.
 */
public class DesEncryptionAndDescryption {
    private static final byte[][] IP_TABLE = {
            {58, 50, 42, 34, 26, 18, 10, 2},
            {60, 52, 44, 36, 28, 20, 12, 4},
            {62, 54, 46, 38, 30, 22, 14, 6},
            {64, 56, 48, 40, 32, 24, 16, 8},
            {57, 49, 41, 33, 25, 17, 9, 1},
            {59, 51, 43, 35, 27, 19, 11, 3},
            {61, 53, 45, 37, 29, 21, 13, 5},
            {63, 55, 47, 39, 31, 23, 15, 7}
    };
    private static final byte[][] IP_INVERSE_TABLE = {
            {40, 8, 48, 16, 56, 24, 64, 32},
            {39, 7, 47, 15, 55, 23, 63, 31},
            {38, 6, 46, 14, 54, 22, 62, 30},
            {37, 5, 45, 13, 53, 21, 61, 29},
            {36, 4, 44, 12, 52, 20, 60, 28},
            {35, 3, 43, 11, 51, 19, 59, 27},
            {34, 2, 42, 10, 50, 18, 58, 26},
            {33, 1, 41, 9, 49, 17, 57, 25}
    };
    private static final byte[][] E_TABLE = {
            {32, 1, 2, 3, 4, 5},
            {4, 5, 6, 7, 8, 9},
            {8, 9, 10, 11, 12, 13},
            {12, 13, 14, 15, 16, 17},
            {16, 17, 18, 19, 20, 21},
            {20, 21, 22, 23, 24, 25},
            {24, 25, 26, 27, 28, 29},
            {28, 29, 30, 31, 32, 1}
    };
    private static final byte[][] P_TABLE = {
            {16, 7, 20, 21, 29, 12, 28, 17},
            {1, 15, 23, 26, 5, 18, 31, 10},
            {2, 8, 24, 14, 32, 27, 3, 9},
            {19, 13, 30, 6, 22, 11, 4, 25}
    };

    private static final byte[][] S1_TABLE = {
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    };
    private static final byte[][] S2_TABLE = {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0 ,5, 14, 9}
    };
    private static final byte[][] S3_TABLE = {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    };
    private static final byte[][] S4_TABLE = {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6 ,9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    };
    private static final byte[][] S5_TABLE = {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    };
    private static final byte[][] S6_TABLE = {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    };
    private static final byte[][] S7_TABLE = {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    };
    private static final byte[][] S8_TABLE = {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    };

    private static final byte[][] KEY_TABLE = {
            {1, 2, 3, 4, 5, 6, 7, 8},
            {9, 10, 11, 12, 13, 14, 15, 16},
            {17, 18, 19, 20, 21, 22, 23, 24},
            {25, 26, 27, 28, 29, 30, 31, 32},
            {33, 34, 35, 36, 37, 38, 39, 40},
            {41, 42, 43, 44, 45, 46, 47, 48},
            {49, 50, 51, 52, 53, 54, 55, 56},
            {57, 58, 59, 60, 61, 62, 63, 64}
    };
    private static final byte[][] REPLACE_SELECTION_TABLE1 = {
            {57, 49, 41, 33, 25, 17, 9},
            {1, 58, 50, 42, 34, 26, 18},
            {10, 2, 59, 51, 43, 35, 27},
            {19, 11, 3, 60, 52, 44, 36},
            {63, 55, 47, 39, 31, 23, 15},
            {7, 62, 54, 46, 38, 30, 22},
            {14, 6, 61, 53, 45, 37, 29},
            {21, 13, 5, 28, 20, 12, 4}
    };
    private static final byte[][] REPLACE_SELECTION_TABLE2 = {
            {14, 17, 11, 24, 1, 5, 3, 28},
            {15, 6, 21, 10, 23, 19, 12, 4},
            {26, 8, 16, 7, 27, 20, 13, 2},
            {41, 52, 31, 37, 47, 55, 30, 40},
            {51, 45, 33, 48, 44, 49, 39, 56},
            {34, 53, 46, 42, 50, 36, 29, 32}
    };
    private static final byte[] CYCLE_SHIFT_TABLE = {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    /**
     * 明文初始替换
     * @param plaintext 明文
     * @return
     */
    public static int[] initReplacement(int[] plaintext){
        int[] plaintext_ip_array = new int[64];
        int k = 0;
        for(int i = 0; i < IP_TABLE.length; i++){
            for(int j = 0; j < IP_TABLE[i].length; j++){
                plaintext_ip_array[k] = plaintext[IP_TABLE[i][j] - 1];
                k++;
            }
        }
        return plaintext_ip_array;
    }

    /**
     * 逆初始替换
     * @param input 16轮迭代结果
     * @return 密文
     */
    public static int[] inverseInitReplacement(int[] input){
        int[] output = new int[64];
        int k = 0;
        for(int i = 0; i < IP_INVERSE_TABLE.length; i++){
            for(int j = 0; j < IP_INVERSE_TABLE[i].length; j++){
                output[k] = input[IP_INVERSE_TABLE[i][j] - 1];
                k++;
            }
        }
        return output;
    }

    /**
     * 密钥的置换选择1
     * @param generateKey 56位密钥
     * @return
     */
    public static int[] replaceSelection1(int[] generateKey){
        int[] generateKey_replace_selection_array = new int[56];
        int k = 0;
        for(int i = 0; i < REPLACE_SELECTION_TABLE1.length; i++){
            for(int j = 0; j < REPLACE_SELECTION_TABLE1[i].length; j++){
                generateKey_replace_selection_array[k] = generateKey[REPLACE_SELECTION_TABLE1[i][j] - 1];
                k++;
            }
        }
        return generateKey_replace_selection_array;
    }

    /**
     * 密钥的循环移位操作
     * @param c 56位密钥左边28位
     * @param d 56位密钥右边28位
     * @param round 轮次
     * @return
     */
    public static int[] leftShiftOperation(int[] c, int[] d, int round){
        int[] c_left_shift_array = new int[28];
        int[] d_left_shift_array = new int[28];
        int[] key_left_shift_array = new int[56];
        //移位次数
        int count = CYCLE_SHIFT_TABLE[round - 1];
        for(int i = 0; i < c.length; i++){
            c_left_shift_array[(i + 28 - count) % 28] = c[i];
            d_left_shift_array[(i + 28 - count) % 28] = d[i];
        }
        for(int i = 0; i < c_left_shift_array.length; i++){
            key_left_shift_array[i] = c_left_shift_array[i];
            key_left_shift_array[28 + i] = d_left_shift_array[i];
        }
        return key_left_shift_array;
    }

    /**
     * 密钥的置换选择2
     * @param key 56位密钥
     * @return 48位密钥
     */
    public static int[] replaceSelection2(int[] key){
        int[] key_replace_selection_array = new int[48];
        int k = 0;
        for(int i = 0; i < REPLACE_SELECTION_TABLE2.length; i++){
            for(int j = 0; j < REPLACE_SELECTION_TABLE2[i].length; j++){
                key_replace_selection_array[k] = key[REPLACE_SELECTION_TABLE2[i][j] - 1];
                k++;
            }
        }
        return key_replace_selection_array;
    }

    /**
     * 将r进行扩充置换成48位
     * @param r 32位数组
     * @return 48位数组
     */
    public static int[] expandReplace(int[] r){
        int[] r_expand_replace_array = new int[48];
        int k = 0;
        for(int i = 0; i < E_TABLE.length; i++){
            for(int j = 0; j < E_TABLE[i].length; j++){
                r_expand_replace_array[k] = r[E_TABLE[i][j] - 1];
                k++;
            }
        }
        return r_expand_replace_array;
    }

    /**
     * 异或操作
     * @param r
     * @param k
     * @return
     */
    public static int[] exclusiveOr(int[] r, int[] k){
        int[] result = new int[r.length];
        for(int i = 0; i < r.length; i++){
            result[i] = r[i] ^ k[i];
        }
        return result;
    }

    /**
     * 代换选择(S盒)函数
     * @param input
     * @return
     */
    public static int[] sFunction(int[] input){
        int[][] s = new int[8][6];
        int[] result = new int[32];
        int k = 0;
        for(int i = 0; i < input.length; i++){
            if(i / 6 == 0){
                s[0][i] = input[i];
            }else if(i / 6 == 1){
                s[1][i - 6] = input[i];
            }else if(i / 6 == 2){
                s[2][i - 12] = input[i];
            }else if(i / 6 == 3){
                s[3][i - 18] = input[i];
            }else if(i / 6 == 4){
                s[4][i - 24] = input[i];
            }else if(i / 6 == 5){
                s[5][i - 30] = input[i];
            }else if(i / 6 == 6){
                s[6][i - 36] = input[i];
            }else {
                s[7][i - 42] = input[i];
            }
        }
        for(int i = 0; i < s.length; i++){
            StringBuilder row_sb = new StringBuilder();
            StringBuilder col_sb = new StringBuilder();
            row_sb.append(s[i][0]);
            row_sb.append(s[i][5]);
            for(int j = 0; j < 4; j++){
                col_sb.append(s[i][j + 1]);
            }
            String row_string = row_sb.toString();
            String col_string = col_sb.toString();
            // 二进制转十进制
            int row = Integer.valueOf(row_string, 2);
            int col = Integer.valueOf(col_string, 2);
            int number = 0;
            if(i == 0){
                number = S1_TABLE[row][col];
            }else if (i == 1){
                number = S2_TABLE[row][col];
            }else if (i == 2){
                number = S3_TABLE[row][col];
            }else if (i == 3){
                number = S4_TABLE[row][col];
            }else if (i == 4){
                number = S5_TABLE[row][col];
            }else if (i == 5){
                number = S6_TABLE[row][col];
            }else if (i == 6){
                number = S7_TABLE[row][col];
            }else if (i == 7){
                number = S8_TABLE[row][col];
            }
            // 十进制转二进制
            String binary_number = Integer.toBinaryString(number);
            if(binary_number.length() != 4){
                int need_length = 4 - binary_number.length();
                StringBuilder bnsb = new StringBuilder();
                for(int l = 0; l < need_length; l++){
                    bnsb.append("0");
                }
                bnsb.append(binary_number);
                binary_number = bnsb.toString();
            }
            for(int l = 0; l < binary_number.length(); l++){
                result[k] = Integer.parseInt(String.valueOf(binary_number.charAt(l)));
                k++;
            }
        }
        return result;
    }

    /**
     * 置换选择P函数
     * @param input
     * @return
     */
    public static int[] replaceSelectionP(int[] input){
        int[] output = new int[32];
        int k = 0;
        for(int i = 0; i < P_TABLE.length; i++){
            for(int j = 0; j < P_TABLE[i].length; j++){
                output[k] = input[P_TABLE[i][j] - 1];
                k++;
            }
        }
        return output;
    }

    /**
     * f函数
     * @param r
     * @param k
     * @return
     */
    public static int[] fFunction(int[] r, int[] k){
        int[] r_expand_replace_array = expandReplace(r);
        int[] s_input = exclusiveOr(r_expand_replace_array, k);
        int[] s_output = sFunction(s_input);
        int[] p_output = replaceSelectionP(s_output);
        return p_output;
    }

    /**
     * 生成十六轮次所需要的密钥
     * @param key 64位密钥
     * @return
     */
    public static int[][] generateKey(int[] key){
        int[][] key_generate = new int[16][48];
        int[] replace_selection1_array = replaceSelection1(key);
        int[] c = new int[28];
        int[] d = new int[28];
        for(int i = 0; i < c.length; i++){
            c[i] = replace_selection1_array[i];
            d[i] = replace_selection1_array[28 + i];
        }
        for(int i = 1; i <= 16; i++){
            int[] left_shift_result = leftShiftOperation(c, d, i);
            int[] replace_selection2_array = replaceSelection2(left_shift_result);
            key_generate[i - 1] = replace_selection2_array;
            for(int j = 0; j < c.length; j++){
                c[i] = left_shift_result[i];
                d[i] = left_shift_result[28 + i];
            }
        }
        return key_generate;
    }

    /**
     * 每轮函数操作
     * @param l
     * @param r
     * @param key_generate
     * @param round
     * @return
     */
    public static Map<String, int[]> roundFunction(int[] l, int[] r, int[][] key_generate, int round){
        Map<String, int[]> result_map = new HashMap<>();
        result_map.put("l", r);
        result_map.put("r", exclusiveOr(l, fFunction(r, key_generate[round - 1])));
        return result_map;
    }

    /**
     * DES加密
     * @param plaintext 明文
     * @param key 密文
     * @return
     */
    public static int[] desEncrypt(int[] plaintext, int[] key){
        int[] init_replacement_array = initReplacement(plaintext);
        int[] result_array = new int[64];
        int[][] key_generate = generateKey(key);
        int[] l = new int[32];
        int[] r = new int[32];
        for(int i = 0; i < l.length; i++){
            l[i] = init_replacement_array[i];
            r[i] = init_replacement_array[i + 32];
        }
        for(int j = 1; j <= 16; j++){
            Map<String, int[]> result_map = roundFunction(l, r, key_generate, j);
            l = result_map.get("l");
            r = result_map.get("r");
        }
        for(int i = 0; i < r.length; i++){
            result_array[i] = r[i];
            result_array[32 + i] = l[i];
        }
        int[] output = inverseInitReplacement(result_array);
        return output;
    }

    /**
     * DES解密
     * @param ciphertext 密文
     * @param key 密钥
     * @return
     */
    public static int[] desDescrypt(int[] ciphertext, int[] key){
        int[] init_replacement_array = initReplacement(ciphertext);
        int[] result_array = new int[64];
        int[][] key_generate = generateKey(key);
        int[] l = new int[32];
        int[] r = new int[32];
        for(int i = 0; i < l.length; i++){
            l[i] = init_replacement_array[i];
            r[i] = init_replacement_array[i + 32];
        }
        for(int j = 16; j >= 1; j--){
            Map<String, int[]> result_map = roundFunction(l, r, key_generate, j);
            l = result_map.get("l");
            r = result_map.get("r");
        }
        for(int i = 0; i < r.length; i++){
            result_array[i] = r[i];
            result_array[32 + i] = l[i];
        }
        int[] output = inverseInitReplacement(result_array);
        return output;
    }

}
