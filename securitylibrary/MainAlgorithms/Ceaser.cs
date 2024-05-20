using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        static string letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            string cipherText = "";

            //check the plain text is upper or lower case
            if (plainText == plainText.ToUpper()) { letters = letters.ToUpper(); } //if Upper Case
            else if (plainText == plainText.ToLower()) { letters = letters.ToLower(); } //if Upper Case
            else { letters = letters.ToLower(); plainText = plainText.ToLower(); } //if Not Upper Or Lower Make It Lower

            //C = (index of P + key) mod 26
            for (int i = 0; i < plainText.Length; i++)
            {
                int indexPlain = letters.IndexOf(plainText[i]);
                int indexcipher = (indexPlain + key) % 26;
                cipherText += letters[indexcipher];
            }
            return cipherText.ToUpper();
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            string plianText = "";

            //check the plain text is upper or lower case
            if (cipherText == cipherText.ToUpper()) { letters = letters.ToUpper(); } //if Upper Case
            else if (cipherText == cipherText.ToLower()) { letters = letters.ToLower(); } //if Upper Case
            else { letters = letters.ToLower(); cipherText = cipherText.ToLower(); } //if Not Upper Or Lower Make It Lower

            //C = (index of P + key) mod 26
            for (int i = 0; i < cipherText.Length; i++)
            {
                int indexcipher = letters.IndexOf(cipherText[i]);
                int indexPlain = (indexcipher - key) % 26;
                if (indexPlain < 0) { indexPlain = 26 + indexPlain; }

                plianText += letters[indexPlain];
            }
            return plianText.ToLower();
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();

            int key = 0;
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            letters = letters.ToLower();

            //C = (index of P + key) mod 26
            int indexPlain = letters.IndexOf(plainText[0]);
            int indexcipher = letters.IndexOf(cipherText[0]);

            if (indexcipher > indexPlain) { key = indexcipher - indexPlain; }
            else if (indexcipher < indexPlain) { key = indexcipher + (26 - indexPlain); }

            return key;
        }
    }
}
