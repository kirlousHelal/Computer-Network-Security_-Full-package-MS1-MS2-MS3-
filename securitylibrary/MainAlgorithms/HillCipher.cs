using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            if (plainText == null || cipherText == null || plainText.Count != cipherText.Count)
            {
                throw new InvalidAnlysisException();
            }

            List<int> foundKey = null;

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            List<int> key = new List<int> { l, k, j, i };
                            List<int> encryptedText = Encrypt(plainText, key);

                            if (Enumerable.SequenceEqual(encryptedText, cipherText))
                            {
                                foundKey = key;
                                return foundKey; // Exit early if key is found
                            }
                        }
                    }
                }
            }

            throw new InvalidAnlysisException(); // If no key is found
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
        private List<int> MatrixToList(int[,] matrix)
        {
            return matrix.Cast<int>().ToList();
        }


        private int[,] List_to_Matrix(List<int> key)
        {
            int[,] keyMatrix;
            int count;
            if (key.Count % 2 == 0)
            {
                keyMatrix = new int[2, 2];
                count = 0;
                for (int x = 0; x < 2; x++)
                {
                    for (int y = 0; y < 2; y++)
                    {
                        keyMatrix[x, y] = key[count];
                        count++;
                    }
                }
            }
            else if (key.Count % 3 == 0)
            {
                keyMatrix = new int[3, 3];
                count = 0;
                for (int x = 0; x < 3; x++)
                {
                    for (int y = 0; y < 3; y++)
                    {
                        keyMatrix[x, y] = key[count];
                        count++;
                    }
                }
            }
            else
                keyMatrix = new int[3, 2];
            return keyMatrix;
        }
        private int CalculateDeterminant(int[,] matrix)
        {
            int size = matrix.GetLength(0);

            if (size == 1)
                return matrix[0, 0];

            else if (size == 2)
                return (matrix[0, 0] * matrix[1, 1]) - (matrix[0, 1] * matrix[1, 0]);

            else
            {
                int determinant = 0;

                for (int j = 0; j < size; j++)
                {
                    int[,] submatrix = new int[size - 1, size - 1];
                    for (int i = 1; i < size; i++)
                    {
                        for (int k = 0; k < size; k++)
                        {
                            if (k < j)
                                submatrix[i - 1, k] = matrix[i, k];
                            else if (k > j)
                                submatrix[i - 1, k - 1] = matrix[i, k];
                        }
                    }

                    int sign = (j % 2 == 0) ? 1 : -1;

                    determinant += sign * matrix[0, j] * CalculateDeterminant(submatrix);
                }
                return determinant;
            }
        }

        private int[,] GetMinorMatrix(int[,] matrix, int row, int column)
        {
            int size = matrix.GetLength(0);
            int[,] minorMatrix = new int[size - 1, size - 1];
            int minorRow = 0, minorColumn = 0;

            for (int i = 0; i < size; i++)
            {
                if (i == row)
                    continue;

                minorColumn = 0;
                for (int j = 0; j < size; j++)
                {
                    if (j == column)
                        continue;

                    minorMatrix[minorRow, minorColumn] = matrix[i, j];
                    minorColumn++;
                }
                minorRow++;
            }
            return minorMatrix;
        }


        private int Mod(int dividend, int divisor)
        {
            if (divisor == 0)
                throw new ArgumentException("Divisor cannot be zero.");

            int remainder = dividend % divisor;
            if (remainder < 0)
                remainder += divisor;

            return remainder;
        }

        private int findMultiplicativeInverse(int det)
        {
            for (int i = 1; i < 26; i++)
            {
                if ((i * det) % 26 == 1)
                {
                    return i;
                }
            }
            return -1;
        }

        private int[,] FlipMatrix(int[,] matrix)
        {
            int size = matrix.GetLength(0);
            int[,] flippedMatrix = new int[size, size];

            for (int row = 0; row < size; row++)
            {
                for (int col = 0; col < size; col++)
                {
                    if (row == col)
                        flippedMatrix[row, col] = matrix[size - 1 - row, size - 1 - col];
                    else
                        flippedMatrix[row, col] = -matrix[row, col];
                }
            }

            return flippedMatrix;
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> ptext = new List<int>();

            int[,] keyMatrix = List_to_Matrix(key);
            int det = Mod(CalculateDeterminant(keyMatrix), 26);

            if (keyMatrix.GetLength(0) != keyMatrix.GetLength(1))
                throw new System.Exception("Key matrix must be square.");

            int[,] keyMatInverse = new int[keyMatrix.GetLength(0), keyMatrix.GetLength(1)];

            if (keyMatrix.GetLength(0) == 3)
            {
                int b = findMultiplicativeInverse(det);

                for (int i = 0; i < keyMatrix.GetLength(0); i++)
                {
                    for (int j = 0; j < keyMatrix.GetLength(1); j++)
                    {
                        int[,] minorMatrix = GetMinorMatrix(keyMatrix, j, i);
                        int subdet = Mod(CalculateDeterminant(minorMatrix), 26);
                        keyMatInverse[i, j] = Mod(b * (int)Math.Pow(-1, i + j) * subdet, 26);
                    }
                }

                List<int> keyInverseList = MatrixToList(keyMatInverse);

                for (int k = 0; k < cipherText.Count; k += 3)
                {
                    for (int i = 0; i < keyInverseList.Count; i += 3)
                    {
                        int sum = 0;
                        for (int j = 0; j < 3; j++)
                        {
                            sum += keyInverseList[i + j] * cipherText[k + j];
                        }
                        ptext.Add(Mod(sum, 26));
                    }
                }
            }
            else if (keyMatrix.GetLength(0) == 2)
            {
                det = CalculateDeterminant(keyMatrix);
                int[,] flipMatrix = FlipMatrix(keyMatrix);

                for (int i = 0; i < keyMatInverse.GetLength(0); i++)
                {
                    for (int j = 0; j < keyMatInverse.GetLength(1); j++)
                    {
                        keyMatInverse[i, j] = Mod(((1 / det) * flipMatrix[i, j]), 26);
                    }
                }

                List<int> keyInverseList = MatrixToList(keyMatInverse);

                for (int k = 0; k < cipherText.Count; k += 2)
                {
                    for (int i = 0; i < keyInverseList.Count; i += 2)
                    {
                        int sum = 0;
                        for (int j = 0; j < 2; j++)
                        {
                            sum += keyInverseList[i + j] * cipherText[k + j];
                        }
                        ptext.Add(Mod(sum, 26));
                    }
                }
            }

            if (ptext.All(s => s == 0))
                throw new System.Exception("Invalid decryption result.");

            return ptext;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> ctext = new List<int>();

            if (key.Count % 2 == 0)
            {
                for (int k = 0; k < plainText.Count; k += 2)
                {
                    for (int i = 0; i < key.Count; i += 2)
                    {
                        int sum = key[i] * plainText[k] + key[i + 1] * plainText[k + 1];
                        ctext.Add(Mod(sum, 26));
                    }
                }
            }
            else if (key.Count % 3 == 0)
            {
                for (int k = 0; k < plainText.Count; k += 3)
                {
                    for (int i = 0; i < key.Count; i += 3)
                    {
                        int sum = key[i] * plainText[k] + key[i + 1] * plainText[k + 1] + key[i + 2] * plainText[k + 2];
                        ctext.Add(Mod(sum, 26));
                    }
                }
            }

            return ctext;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public int GCD(int num1, int num2)
        {
            int Remainder;

            while (num2 != 0)
            {
                Remainder = num1 % num2;
                num1 = num2;
                num2 = Remainder;
            }

            return num1;
        }
        public int DetMatrix2X2(int a, int b, int c, int d, int sign)
        {

            if (sign == 1)
            {
                return (((((a * d) - (b * c)) % 26) + 26) % 26);
            }
            else
            {
                return (((((b * c) - (a * d)) % 26) + 26) % 26);

            }

        }
        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            List<int> plaintext = new List<int>();
            int[,] matrixkey = new int[3, 3];
            int[,] matrixcipher = new int[3, 1];
            int count = 0;
            int det = 0;
            int b = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (plain3[count] < 0 || plain3[count] > 26)
                    {
                        throw new InvalidAnlysisException();
                    }
                    else
                    {
                        matrixkey[i, j] = plain3[count];
                        count++;
                    }
                }
            }
            count = 0;
            for (int i = 0; i < 3; i++)
                det = det + (matrixkey[0, i] * (matrixkey[1, (i + 1) % 3] * matrixkey[2, (i + 2) % 3] - matrixkey[1, (i + 2) % 3] * matrixkey[2, (i + 1) % 3]));
            det = ((det % 26) + 26) % 26;
            for (int i = 0; i < 26; i++)
            {
                if ((((i * det) % 26) + 26) % 26 == 1)
                {
                    b = i;
                    break;
                }
            }

            if (det == 0 || GCD(26, det) != 1 || b == 0)
                throw new InvalidAnlysisException();
            int[,] inverse_key_matrix = new int[3, 3];
            int[,] transpose_matrix = new int[3, 3];
            int temp;
            int z;
            int[] signs = new int[] { 1, 0, 1, 0, 1, 0, 1, 0, 1 };
            int c = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    temp = b * Convert.ToInt32(Math.Pow(-1, i + j));
                    z = DetMatrix2X2(matrixkey[(i + 1) % 3, (j + 1) % 3], matrixkey[(i + 1) % 3, (j + 2) % 3], matrixkey[(i + 2) % 3, (j + 1) % 3], matrixkey[(i + 2) % 3, (j + 2) % 3], signs[c]);
                    c++;
                    inverse_key_matrix[i, j] = (((temp * z) % 26) + 26) % 26;
                    transpose_matrix[j, i] = inverse_key_matrix[i, j];
                }
            }
            count = 0;
            int acc = 0;
            int[,] test = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    test[i, j] = cipher3[count];
                    count++;
                }
            }
            count = 0;
            for (int i = 0; i < cipher3.Count / 3; i++)
            {

                for (int cc = 0; cc < 3; cc++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        acc += (transpose_matrix[count, j] * test[j, cc]);
                    }
                    plaintext.Add(((acc % 26) + 26) % 26);
                    acc = 0;
                }
                count++;
            }
            count = 0;
            int[,] show = new int[3, 3];
            int[,] show_x = new int[3, 3];

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    show[i, j] = plaintext[count];
                    count++;
                }
            }
            count = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    show_x[j, i] = show[i, j];

                }
            }
            List<int> t = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    t.Add(show_x[i, j]);
                }
            }
            return t;

        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}