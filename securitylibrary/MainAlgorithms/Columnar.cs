using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            List<int> keyList = null;

            for (int key = 2; key <= cipherText.Length; key++)
            {
                int rows = (int)Math.Ceiling(cipherText.Length / (double)key);
                List<List<char>> matrix = new List<List<char>>();

                for (int i = 0, index = 0; i < rows; i++)
                {
                    matrix.Add(new List<char>());
                    foreach (var j in Enumerable.Range(0, key))
                    {
                        if (index < plainText.Length)
                            matrix[i].Add(plainText[index++]);
                        else
                            matrix[i].Add(' '); // Padding if plainText is shorter than expected
                    }
                }

                StringBuilder decipheredText = new StringBuilder();
                foreach (var c in Enumerable.Range(0, key))
                {
                    foreach (var r in Enumerable.Range(0, rows))
                        decipheredText.Append(matrix[r][c]);
                }

                int currentIndex = 0;
                keyList = new List<int>();

                foreach (var cc in Enumerable.Range(0, decipheredText.Length - rows + 1).Where(cc => cc % rows == 0))
                {
                    string currentSubstring = decipheredText.ToString().Substring(cc, rows);
                    foreach (var t in Enumerable.Range(0, cipherText.Length - rows + 1).Where(t => t % rows == 0))
                    {
                        string compareSubstring = cipherText.Substring(t, rows);
                        if (currentSubstring.Equals(compareSubstring))
                        {
                            keyList.Add((t / rows) + 1);
                            break;
                        }
                    }
                    currentIndex = cc + rows;
                }

                if (key == keyList.Count)
                    break;
            }
            return keyList;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.ToLower();
            char[,] mtrx = new char[cipherText.Length / key.Count, key.Count];
            char[,] mtrx2 = new char[cipherText.Length / key.Count, key.Count];
            int dd = 0, idx = 0;

            foreach (var d in Enumerable.Range(0, key.Count))
            {
                foreach (var ddd in Enumerable.Range(0, cipherText.Length / key.Count))
                    mtrx[ddd, dd] = cipherText[idx++];
                dd++;
            }

            for (int i = 0; i < key.Count; i++)
            {
                int old_matrix_column = key[i] - 1;
                foreach (var j in Enumerable.Range(0, cipherText.Length / key.Count))
                    mtrx2[j, i] = mtrx[j, old_matrix_column];
            }

            StringBuilder plain = new StringBuilder();
            foreach (var i in Enumerable.Range(0, cipherText.Length / key.Count))
            {
                foreach (var j in Enumerable.Range(0, key.Count))
                    plain.Append(mtrx2[i, j]);
            }
            return plain.ToString().ToUpper();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            // Calculate the length of the row (# chars step) 
            int row = (int)Math.Ceiling((double)plainText.Length / key.Count);
            int col = key.Count;

            // Filling the matrix -> row wise
            Dictionary<Tuple<int, int>, char> dict = new Dictionary<Tuple<int, int>, char>();
            foreach (var r in Enumerable.Range(0, row))
            {
                foreach (var c in Enumerable.Range(0, col))
                {
                    int count = r * col + c;
                    if (count < plainText.Length)
                        dict.Add(Tuple.Create(r, c), plainText[count]);
                    else
                        dict.Add(Tuple.Create(r, c), 'x');
                }
            }

            // Extract the cipher text -> columns wise
            StringBuilder cipherText = new StringBuilder();
            foreach (var c in Enumerable.Range(0, col))
            {
                foreach (var r in Enumerable.Range(0, row))
                    cipherText.Append(dict[Tuple.Create(r, key.IndexOf(c + 1))]);
            }
            return cipherText.ToString();
        }
    }
}
