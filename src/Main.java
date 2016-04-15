/**
 * Created by ljkey on 2016/3/29.
 */
public class Main {
    public static void main(String[] args){
        String key1 = "1110001011110110110111100011000000111010000010000110001011011100";
        String key2 = "0110001011110110110111100011000000111010000010000110001011011100";
        String plaintext = "0110100010000101001011110111101000010011011101101110101110100100";
        int[] key_array1 = new int[64];
        int[] key_array2 = new int[64];
        int[] plaintext_array = new int[64];
        for(int i = 0; i < key_array1.length; i++){
            key_array1[i] = Integer.parseInt(String.valueOf(key1.charAt(i)));
            key_array2[i] = Integer.parseInt(String.valueOf(key2.charAt(i)));
            plaintext_array[i] = Integer.parseInt(String.valueOf(plaintext.charAt(i)));
        }
        int[] ciphertext1 = DesAlgorithm.desEncrypt(plaintext_array, key_array1);
        int[] ciphertext2 = DesAlgorithm.desEncrypt(plaintext_array, key_array2);
        System.out.print("用密钥1加密后的密文:");
        printIntArray(ciphertext1);
        System.out.print("用密钥2加密后的密文:");
        printIntArray(ciphertext2);
        System.out.println("两组密文不同数据位的数量: " + computeDifferent(ciphertext1, ciphertext2));
    }

    public static void printIntArray(int[] a){
        for(int i = 0;i < a.length; i++){
            if ((i + 1) % 8 == 0){
                System.out.print(a[i] + " ");
            }else {
                System.out.print(a[i]);
            }
        }
        System.out.println();
    }

    public static int computeDifferent(int[] a, int[] b){
        int sum = 0;
        for(int i = 0; i < a.length; i++){
            if(a[i] != b[i])
                sum += 1;
        }
        return sum;
    }
}
