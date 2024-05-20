using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            byte[] keyBytes = key.StartsWith("0x") ? Hex(key.Substring(2)) : Encoding.Default.GetBytes(key);
            byte[] cipherBytes = cipherText.StartsWith("0x") ? Hex(cipherText.Substring(2)) : Encoding.Default.GetBytes(cipherText);

            byte[] plainBytes = new byte[cipherBytes.Length];

            int[] S = Enumerable.Range(0, 256).ToArray();
            for (int i = 0, j = 0; i < 256; i++)
            {
                j = (j + S[i] + keyBytes[i % keyBytes.Length]) % 256;
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }

            int x = 0, y = 0;
            for (int i = 0; i < cipherBytes.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + S[x]) % 256;
                int temp = S[x];
                S[x] = S[y];
                S[y] = temp;
                plainBytes[i] = (byte)(cipherBytes[i] ^ S[(S[x] + S[y]) % 256]);
            }

            return cipherText.StartsWith("0x") ?
                "0x" + BitConverter.ToString(plainBytes).Replace("-", "").ToLower() :
                Encoding.Default.GetString(plainBytes);
        }

        public override string Encrypt(string plainText, string key)
        {
            byte[] key_arr;
            byte[] plainText_arr;

            int[] X = new int[256];
            byte[] Y = new byte[256];

            int n = 0;
            int m = 0;

            if (key.StartsWith("0x"))
            {
                key_arr = Hex(key.Substring(2));
            }
            else
            {
                key_arr = Encoding.ASCII.GetBytes(key);
            }

            if (plainText.StartsWith("0x"))
            {
                plainText_arr = Hex(plainText.Substring(2));
            }
            else
            {
                plainText_arr = Encoding.ASCII.GetBytes(plainText);
            }

            byte[] cipher_arr = new byte[plainText_arr.Length];

            for (int i = 0; i < 256; i++)
            {
                Y[i] = key_arr[i % key_arr.Length];
                X[i] = i;
            }

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                int temp = X[i];
                j = (j + X[i] + Y[i]) % 256;
                X[i] = X[j];
                X[j] = temp;
            }

            for (int i = 0; i < plainText_arr.Length; i++)
            {
                n = (n + 1) % 256;
                int temp = X[n];
                m = (m + X[n]) % 256;
                X[n] = X[m];
                X[m] = temp;
                cipher_arr[i] = (byte)(plainText_arr[i] ^ X[(X[n] + X[m]) % 256]);
            }

            if (plainText.StartsWith("0x"))
            {
                return "0x" + BitConverter.ToString(cipher_arr).Replace("-", "").ToLower();
            }
            else
            {
                return Encoding.Default.GetString(cipher_arr);
            }
        }
        public static byte[] Hex(string hex)
        {
            int L = hex.Length;
            byte[] bytes = new byte[L / 2];

            for (int i = 0; i < L; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }
    }
}