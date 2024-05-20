using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        /// 
        string letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";



        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();


            //return plainText;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            letters = letters.ToLower();

            string plainText = "";
            char[,] keyMatrix = genrateMatrixKey(cipherText, key);

            string copyCipherText = cipherText;

            while (copyCipherText.Length != 0)
            {
                string firstTwoChars = copyCipherText.Substring(0, 2);
                copyCipherText = copyCipherText.Remove(0, 2);

                var plainFirstLetter = findIndex_2D(keyMatrix, firstTwoChars[0]);
                var plainSecondLetter = findIndex_2D(keyMatrix, firstTwoChars[1]);

                var cipherFirstLetter = (-1, -1);
                var cipherSecondLetter = (-1, -1);

                //if The Same Row
                if (plainFirstLetter.Item1 == plainSecondLetter.Item1)
                {
                    //First Letter
                    cipherFirstLetter.Item1 = plainFirstLetter.Item1;
                    cipherFirstLetter.Item2 = (plainFirstLetter.Item2 - 1);
                    if (cipherFirstLetter.Item2 < 0) cipherFirstLetter.Item2 = 5 + cipherFirstLetter.Item2;

                    //Second Letter
                    cipherSecondLetter.Item1 = plainSecondLetter.Item1;
                    cipherSecondLetter.Item2 = (plainSecondLetter.Item2 - 1);
                    if (cipherSecondLetter.Item2 < 0) cipherSecondLetter.Item2 = 5 + cipherSecondLetter.Item2;
                }
                //if The Same Column
                else if (plainFirstLetter.Item2 == plainSecondLetter.Item2)
                {
                    //First Letter
                    cipherFirstLetter.Item1 = (plainFirstLetter.Item1 - 1);
                    if (cipherFirstLetter.Item1 < 0) cipherFirstLetter.Item1 = 5 + cipherFirstLetter.Item1;
                    cipherFirstLetter.Item2 = plainFirstLetter.Item2;

                    //Second Letter
                    cipherSecondLetter.Item1 = (plainSecondLetter.Item1 - 1);
                    if (cipherSecondLetter.Item1 < 0) cipherSecondLetter.Item1 = 5 + cipherSecondLetter.Item1;
                    cipherSecondLetter.Item2 = plainSecondLetter.Item2;
                }
                // Different Rows and Columns
                else
                {
                    //First Letter
                    cipherFirstLetter.Item1 = plainFirstLetter.Item1;
                    cipherFirstLetter.Item2 = plainSecondLetter.Item2;

                    //Second Letter
                    cipherSecondLetter.Item1 = plainSecondLetter.Item1;
                    cipherSecondLetter.Item2 = plainFirstLetter.Item2;
                }

                plainText += keyMatrix[cipherFirstLetter.Item1, cipherFirstLetter.Item2];
                plainText += keyMatrix[cipherSecondLetter.Item1, cipherSecondLetter.Item2];

            }

            //Remove letter "x"
            string copyPlainText = "";
            for (int i = 0; i < plainText.Length - 1; i++)
            {
                if (plainText[i] == 'x' && i % 2 != 0 && plainText[i - 1] == plainText[i + 1])
                    continue;
                copyPlainText += plainText[i];

            }
            if (plainText[plainText.Length - 1] != 'x') copyPlainText += plainText[plainText.Length - 1];

            return copyPlainText.ToLower();
        }


        public char[,] genrateMatrixKey(string plainText, string key)
        {
            string copyLetters = letters;

            // Make The Number of Letters 25 Letter
            if (plainText.Contains("j")) // then the matrix will have the "j" not "i"
            {
                copyLetters = copyLetters.Replace("i", "");//delete letter "i"
                key = key.Replace("i", "j"); // replace all "i" in the key to "j"
            }
            else // then the matrix will have the "i" not "j"
            {
                copyLetters = copyLetters.Replace("j", "");//delete letter "j"
                key = key.Replace("j", "i"); // replace all "j" in the key to "i"
            }


            char[,] keyMatrix = new char[5, 5];
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (key.Length != 0)
                    {
                        keyMatrix[i, j] = key[0];

                        // Remove all occurrences of the letter 'key[countKey]' In The Letters
                        copyLetters = copyLetters.Replace(key[0].ToString(), "");

                        // Remove all occurrences of the letter 'key[countKey] In The Keyword'
                        key = key.Replace(key[0].ToString(), "");
                    }
                    else if (copyLetters.Length != 0)
                    {
                        keyMatrix[i, j] = copyLetters[0];

                        // Remove all occurrences of the letter 'key[countKey]' In The Letters
                        copyLetters = copyLetters.Replace(copyLetters[0].ToString(), "");
                    }
                }
            }
            return keyMatrix;
        }

        public (int, int) findIndex_2D(char[,] keyMatrix, char letter)
        {
            var indices = (-1, -1);
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (keyMatrix[i, j] == letter) return (i, j);

                }
            }

            return indices;
        }



        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            key = key.ToLower();
            letters = letters.ToLower();

            string cipherText = "";
            char[,] keyMatrix = genrateMatrixKey(plainText, key);


            string copyPlainText = plainText;

            while (copyPlainText.Length != 0)
            {
                if (copyPlainText.Length == 1) { copyPlainText += "x"; }
                string firstTwoChars;
                if (copyPlainText[0] == copyPlainText[1])
                {
                    firstTwoChars = copyPlainText.Substring(0, 1);
                    copyPlainText = copyPlainText.Remove(0, 1);
                    firstTwoChars += "x";
                }
                else
                {
                    firstTwoChars = copyPlainText.Substring(0, 2);
                    copyPlainText = copyPlainText.Remove(0, 2);
                }

                var plainFirstLetter = findIndex_2D(keyMatrix, firstTwoChars[0]);
                var plainSecondLetter = findIndex_2D(keyMatrix, firstTwoChars[1]);

                var cipherFirstLetter = (-1, -1);
                var cipherSecondLetter = (-1, -1);

                //if The Same Row
                if (plainFirstLetter.Item1 == plainSecondLetter.Item1)
                {
                    //First Letter
                    cipherFirstLetter.Item1 = plainFirstLetter.Item1;
                    cipherFirstLetter.Item2 = (plainFirstLetter.Item2 + 1) % 5;

                    //Second Letter
                    cipherSecondLetter.Item1 = plainSecondLetter.Item1;
                    cipherSecondLetter.Item2 = (plainSecondLetter.Item2 + 1) % 5;
                }
                //if The Same Column
                else if (plainFirstLetter.Item2 == plainSecondLetter.Item2)
                {
                    //First Letter
                    cipherFirstLetter.Item1 = (plainFirstLetter.Item1 + 1) % 5;
                    cipherFirstLetter.Item2 = plainFirstLetter.Item2;

                    //Second Letter
                    cipherSecondLetter.Item1 = (plainSecondLetter.Item1 + 1) % 5;
                    cipherSecondLetter.Item2 = plainSecondLetter.Item2;
                }
                // Different Rows and Columns
                else
                {
                    //First Letter
                    cipherFirstLetter.Item1 = plainFirstLetter.Item1;
                    cipherFirstLetter.Item2 = plainSecondLetter.Item2;

                    //Second Letter
                    cipherSecondLetter.Item1 = plainSecondLetter.Item1;
                    cipherSecondLetter.Item2 = plainFirstLetter.Item2;
                }

                cipherText += keyMatrix[cipherFirstLetter.Item1, cipherFirstLetter.Item2];
                cipherText += keyMatrix[cipherSecondLetter.Item1, cipherSecondLetter.Item2];

            }

            return cipherText.ToUpper();
        }
    }
}
