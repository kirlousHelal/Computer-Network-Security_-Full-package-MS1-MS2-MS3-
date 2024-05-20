using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            string key = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                int shift = (cipherText[i] - plainText[i] + 26) % 26;

                char letter = (char)('a' + shift);

                key += letter;

                if (cipherText.Equals(Encrypt(plainText, key)))
                {
                    break;
                }
            }

            return key;

        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string plainText = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            int x = 0;
            while (key.Length < cipherText.Length)
            {
                key += key[x];
                x++;
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainText += alphabet[(cipherText[i] - key[i] + 26) % 26];
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            int x = 0;
            while (key.Length < plainText.Length)
            {
                key += key[x];
                x++;
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText += alphabet[(plainText[i] - 'a' + key[i] - 'a') % 26];
            }
            return cipherText;
        }
    }
}
