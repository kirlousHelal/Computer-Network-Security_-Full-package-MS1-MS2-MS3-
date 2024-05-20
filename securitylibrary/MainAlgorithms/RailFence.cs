using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {

        public string Encrypt(string plainText, int keySize)
        {
            // Calculate the number of columns for the cipher table
            int columnCount = plainText.Length / keySize;
            if (plainText.Length % keySize != 0)
            {
                columnCount++;
            }

            // The number of rows is equal to the key size
            int rowCount = keySize;

            // Initialize the cipher table with the calculated number of rows and columns
            char[,] cipherTable = new char[rowCount, columnCount];

            // Loop over each character in the plaintext
            for (int i = 0; i < plainText.Length; i++)
            {
                // Calculate the row and column indices for the current character
                int row = i % rowCount;
                int column = i / rowCount;

                // Place the current character in the cipher table
                cipherTable[row, column] = plainText[i];
            }

            // Initialize a StringBuilder to hold the cipher text
            var cipherText = new StringBuilder();

            // Append each character in the cipher table to the cipher text
            foreach (var character in cipherTable)
            {
                cipherText.Append(character);
            }

            // Return the cipher text as a string
            return cipherText.ToString();
        }




        public string Decrypt(string cipherText, int key)
        {
            int col = cipherText.Length / key;
            if (cipherText.Length % key != 0)
                col++;

            char[,] arr = new char[key, col];
            int index = 0;

            // Fill the 2D array with characters from the cipher text
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (index < cipherText.Length)
                        arr[i, j] = cipherText[index++];
                    else
                        arr[i, j] = '*'; // Pad with '*' if the end of the cipher text is reached
                }
            }

            // Construct the decrypted text from the 2D array
            string decryptedText = "";
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    // Append non-pad characters to the decrypted text
                    if (arr[j, i] != '*')
                        decryptedText += arr[j, i];
                }
            }

            // Convert the decrypted text to uppercase and return
            return decryptedText.ToUpper();
        }



        public int Analyse(string plainText, string cipherText)
        {
            for (int key = 1; key <= 100; key++)
            {
                if (string.Equals(Encrypt(plainText, key), cipherText, StringComparison.InvariantCultureIgnoreCase))
                    return key;
            }
            return 0;
        }


    }
}