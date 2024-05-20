using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            string letters = "abcdefghijklmnopqrstuvwxyz";
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            StringBuilder alphabet = new StringBuilder(letters), key = new StringBuilder("                          ");

            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < letters.Length; j++)
                    if (letters[j] == plainText[i])
                        key[j] = cipherText[i];

                for (int j = 0; j < letters.Length; j++)
                    if (letters[j] == cipherText[i])
                        alphabet[j] = '0';
            }

            for (int i = 0; i < alphabet.Length; i++)
                for (int j = i; j < key.Length; j++)
                    if (alphabet[i] != '0' && key[j] == ' ')
                    {
                        key[j] = alphabet[i];
                        alphabet[i] = '0';
                    }

            return key.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            string plain = "";
            char referance = 'a';
            cipherText = cipherText.ToLower();

            for (int i = 0; i < cipherText.Length; i++)
                if (char.IsLetter(cipherText[i]))
                    plain += (char)((int)key.IndexOf(cipherText[i]) + referance);
                else
                    plain += cipherText[i];

            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipher = "";
            char referance = 'a';
            plainText = plainText.ToLower();

            for (int i = 0; i < plainText.Length; i++)
                if (char.IsLetter(plainText[i]))
                    cipher += key[plainText[i] - referance];
                else
                    cipher += plainText[i];

            return cipher;
        }

        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            Dictionary<char, int> frq = new Dictionary<char, int>();
            string permutation = "etaoinsrhldcumfpgwybvkxjqz";
            char[] freq = new char[cipher.Length];
            string outfrq = "";
            int indx = 0;

            for (char i = 'a'; i <= 'z'; i++)
            {
                frq.Add(i, 0);
                for (int j = 0; j < cipher.Length; j++)
                    if (i == cipher[j])
                        frq[i]++;
            }

            foreach (KeyValuePair<char, int> keyvalue in frq.OrderByDescending(key => key.Value))
            {
                for (int i = 0; i < cipher.Length; i++)
                    if (cipher[i] == keyvalue.Key && freq[i] == 0)
                        freq[i] = permutation[indx];

                indx++;
            }

            for (int i = 0; i < freq.Length; i++)
                outfrq += freq[i].ToString();

            return outfrq;
        }
    }
}
