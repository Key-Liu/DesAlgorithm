import sun.security.krb5.internal.crypto.Des;

/**
 * Created by ljkey on 2016/3/29.
 */
public class Main {
    public static void main(String[] args){
        String key = "0000001010010110010010001100010000111000001100000011100001100100";
        String plaintext1 = "0000000000000000000000000000000000000000000000000000000000000000";
        String plaintext2 = "1000000000000000000000000000000000000000000000000000000000000000";
        int[] key_array = new int[64];
        int[] plaintext1_array = new int[64];
        int[] plaintext2_array = new int[64];
        for(int i = 0; i < key.length(); i++){
            try {
                key_array[i] = Integer.parseInt(String.valueOf(key.charAt(i)));
                plaintext1_array[i] = Integer.parseInt(String.valueOf(plaintext1.charAt(i)));
                plaintext2_array[i] = Integer.parseInt(String.valueOf(plaintext2.charAt(i)));
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        int[] ciphertext1 = DesEncryption.desEncrypt(plaintext1_array, key_array);
        int[] output1 = DesEncryption.desDescrypt(ciphertext1, key_array);
        int[] ciphertext2 = DesEncryption.desEncrypt(plaintext2_array, key_array);
        int[] output2 = DesEncryption.desDescrypt(ciphertext2, key_array);
        printIntArray(ciphertext1);
        printIntArray(output1);
        printIntArray(ciphertext2);
        printIntArray(output2);
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
}
