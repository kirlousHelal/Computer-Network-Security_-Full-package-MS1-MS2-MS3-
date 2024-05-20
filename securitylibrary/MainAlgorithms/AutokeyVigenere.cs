using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string map = "abcdefghijklmnopqrstuvwxyz";
            string key = "";
            string temp = "";
            int checker = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                int index = ((map.IndexOf(cipherText[i]) - map.IndexOf(plainText[i])) + 26) % 26;
                char c = map[index];
                if (key != "")
                {
                    if (c != plainText[checker])
                    {
                        temp += c;
                        key = temp;
                        checker = 0;
                    }
                    else
                    {
                        temp += c;
                        checker++;
                    }
                }
                else
                {
                    temp += c;
                    key = temp;
                }
            }
            return key;

        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string map = "abcdefghijklmnopqrstuvwxyz";
            //int pointer = 0;
            try
            {
                key = key.Remove(cipherText.Length);
            }
            catch (Exception e)
            {
                key = key;
            }
            //while (key.Length < cipherText.Length)
            //{
            //    key += cipherText[pointer];
            //    pointer++;
            //}
            string plain = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int index = ((map.IndexOf(cipherText[i]) - map.IndexOf(key[i])) + 26) % 26;
                plain += map[index];
                key += map[index];
            }
            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string map = "abcdefghijklmnopqrstuvwxyz";
            int pointer = 0;
            try
            {
                key = key.Remove(plainText.Length);
            }
            catch (Exception e)
            {
                key = key;
            }
            while (key.Length < plainText.Length)
            {
                key += plainText[pointer];
                pointer++;
            }
            string cipher = "";
            for (int i = 0; i < key.Length; i++)
            {
                int index = (map.IndexOf(key[i]) + map.IndexOf(plainText[i])) % 26;
                cipher += map[index];
            }
            return cipher;
        }
    }
}
