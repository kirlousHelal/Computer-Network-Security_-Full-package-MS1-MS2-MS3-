using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary.AES
{

    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            string[,] Matplain = convertStringToMat(cipherText);
            string[,] Matkey = convertStringToMat(key);
            List<string[,]> Keys = new List<string[,]>();
            Keys.Add(Matkey);
            for (int i = 0; i < 10; i++)
            {
                Matkey = AddRoundKey(Matkey, i);
                Keys.Add(Matkey);
            }
            string[,] stat = stateXORcipherkey(Matplain, Keys[10]);
            for (int i = 9; i >= 1; i--)
            {
                stat = inverse_shift_rows(stat);
                stat = sub_byte(stat, InvSBOXbuilder);
                stat = stateXORcipherkey(stat, Keys[i]);
                stat = MixColumn(stat, InvMixCon);
            }
            stat = inverse_shift_rows(stat);
            stat = sub_byte(stat, InvSBOXbuilder);
            stat = stateXORcipherkey(stat, Keys[0]);
            string str = convertMatToString(stat);
            return str;

        }

        public override string Encrypt(string plainText, string key)
        {
            string[,] Matplain = new string[4, 4];
            string[,] Matkey = new string[4, 4];
            Matplain = convertStringToMat(plainText);
            Matkey = convertStringToMat(key);
            string[,] stat = stateXORcipherkey(Matplain, Matkey);
            for (int i = 0; i < 9; i++)
            {
                stat = sub_byte(stat, SBOXbuilder);
                stat = shift_rows(stat);
                stat = MixColumn(stat, MixCon);
                Matkey = AddRoundKey(Matkey, i);
                stat = stateXORcipherkey(stat, Matkey);
            }
            stat = sub_byte(stat, SBOXbuilder);
            stat = shift_rows(stat);
            Matkey = AddRoundKey(Matkey, 9);
            stat = stateXORcipherkey(stat, Matkey);
            string str = convertMatToString(stat);
            return str;
        }
        public string[,] convertStringToMat(string str)
        {
            string[,] Matriex = new string[4, 4];
            int index = 2;

            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    Matriex[i, j] = "";
                    Matriex[i, j] += str[index];
                    Matriex[i, j] += str[index + 1];
                    index += 2;


                }
            }

            return Matriex;
        }
        public string convertMatToString(string[,] Matrix)
        {
            string str = "0x";

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    str += Matrix[j, i];
                }
            }
            return str;
        }
        public string binToString(string s)
        {
            List<Byte> byteList = new List<Byte>();

            for (int i = 0; i < s.Length; i += 8)
            {
                byteList.Add(Convert.ToByte(s.Substring(i, 8), 2));
            }
            return Encoding.ASCII.GetString(byteList.ToArray());
        }
        public string xor(string mat1, string mat2)
        {
            string xOR = "";
            mat2 = mat2.PadLeft(mat1.Length, '0');
            for (int i = 0; i < mat1.Length; i++)
            {
                if (mat1[i] != mat2[i])
                {
                    xOR += '1';
                }
                else
                {
                    xOR += '0';
                }
            }
            return xOR;
        }
        public int convert_to_int(char stat)
        {
            stat = stat.ToString().ToLower()[0];
            switch (stat)
            {
                case 'a':
                    return 10;
                case 'b':
                    return 11;
                case 'c':
                    return 12;
                case 'd':
                    return 13;
                case 'e':
                    return 14;
                case 'f':
                    return 15;
                default:
                    return Convert.ToInt32(stat.ToString());
            }

        }
        public string[,] SBOXbuilder()
        {
            string[,] SBOX = new string[16, 16] {
           {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
           {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0" },
           {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15" },
           {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75" },
           {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84" },
           {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf" },
           {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8" },
           {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2" },
           {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73" },
           {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db" },
           {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79" },
           {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08" },
           {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a" },
           {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e" },
           {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df" },
           {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16" } };
            return SBOX;
        }
        public string[,] InvSBOXbuilder()
        {
            //inverse of SBOX
            string[,] iSBOX = new string[16, 16] {
           {"52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb" },
           {"7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb" },
           {"54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e" },
           {"08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25" },
           {"72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92" },
           {"6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84" },
           {"90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06" },
           {"d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b" },
           {"3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73" },
           {"96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e" },
           {"47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b" },
           {"fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4" },
           {"1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f" },
           {"60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef" },
           {"a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61" },
           {"17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d" } };
            return iSBOX;
        }
        public string[,] StateGenerator(string s)
        {
            string[,] state = new string[4, 4];
            int row = 0; int col = 0;
            for (int i = 2; i < s.Length; i += 2)
            {
                state[row, col] = s[i].ToString();
                state[row, col] += s[i + 1].ToString();
                col++;
                if (col % 4 == 0)
                {
                    col = 0;
                    row++;
                }
            }
            return state;
        }
        public string HexToBin(string hex)
        {
            return Convert.ToString(Convert.ToInt32(hex, 16), 2).PadLeft(8, '0');
        }
        public string BinToHex(string bin)
        {
            return Convert.ToInt32(bin, 2).ToString("X");
        }
        public List<int> SimplifyCoef(List<int> newSCoef)
        {
            HashSet<int> sCoefSet = new HashSet<int>(newSCoef);
            Dictionary<int, int> map = new Dictionary<int, int>();
            foreach (int c in newSCoef)
            {
                if (map.ContainsKey(c))
                {
                    map[c]++;
                }
                else
                {
                    map[c] = 1;
                }
            }
            List<int> newCoef = new List<int>();
            foreach (int c in sCoefSet)
            {
                if (map[c] % 2 != 0)
                {
                    newCoef.Add(c);
                }
            }
            return newCoef;
        }
        public List<int> Replace(List<int> ls)
        {
            List<int> replaced = new List<int>();
            int[] mapper = { 4, 3, 1, 0 };
            foreach (int item in ls)
            {
                if (item > 7)
                {
                    foreach (int i in mapper)
                    {
                        replaced.Add(i + (item - 8));
                    }
                }
                else
                {
                    replaced.Add(item);
                }
            }
            return replaced;
        }
        public string GFMultiplier(string constMatrix, string state)
        {
            string sBin = HexToBin(state);
            string cBin = HexToBin(constMatrix);
            List<int> sCoef = new List<int>();
            List<int> cCoef = new List<int>();
            for (int i = 0; i < sBin.Length; i++)
            {
                if (sBin[i] == '1')
                {
                    sCoef.Add(7 - i);
                }
            }
            for (int i = 0; i < cBin.Length; i++)
            {
                if (cBin[i] == '1')
                {
                    cCoef.Add(7 - i);
                }
            }
            List<int> newSCoef = new List<int>();
            foreach (int ccoef in cCoef)
            {
                for (int i = 0; i < sCoef.Count; i++)
                {
                    newSCoef.Add(sCoef[i] + ccoef);
                }
            }
            HashSet<int> sCoefSet = new HashSet<int>(newSCoef);
            newSCoef = Replace(newSCoef);
            newSCoef = SimplifyCoef(newSCoef);

            string result = "00000000";
            StringBuilder sb = new StringBuilder(result);

            foreach (int scoef in newSCoef)
            {
                if (scoef < 8)
                {
                    sb[7 - scoef] = '1';
                }
            }
            result = sb.ToString();
            return result;
        }
        public string[,] MixCon()
        {
            string[,] Mix = new string[4, 4]
            {
            {"02","03","01","01"},
            {"01","02","03","01"},
            {"01","01","02","03"},
            {"03","01","01","02"}
            };
            return Mix;
        }
        public string[,] InvMixCon()
        {
            string[,] InvMix = new string[4, 4]
            {
            {"0e","0b","0d","09"},
            {"09","0e","0b","0d"},
            {"0d","09","0e","0b"},
            {"0b","0d","09","0e"}
            };
            return InvMix;
        }
        public string[,] stateXORcipherkey(string[,] state, string[,] cipherkey)
        {
            string[,] result = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[i, j] = BinToHex(xor(HexToBin(state[i, j]), HexToBin(cipherkey[i, j]))).PadLeft(2, '0');
                }
            }

            return result;
        }

        public string[,] sub_byte(string[,] state, Func<string[,]> builder)
        {
            string[,] sbox = builder();
            string[,] stateByte = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int row = convert_to_int(state[i, j][0]);
                    int col = convert_to_int(state[i, j][1]);
                    stateByte[i, j] = sbox[row, col];
                }
            }
            return stateByte;
        }
        public string[,] shift_rows(string[,] state)
        {
            int r = 1;
            string temp = state[r, 0];
            state[r, 0] = state[r, 1];
            state[r, 1] = state[r, 2];
            state[r, 2] = state[r, 3];
            state[r, 3] = temp;
            r++;
            temp = state[r, 0];
            string temp2 = state[r, 1];
            state[r, 0] = state[r, 2];
            state[r, 1] = state[r, 3];
            state[r, 2] = temp;
            state[r, 3] = temp2;
            r++;
            temp = state[r, 0];
            temp2 = state[r, 1];
            string temp3 = state[r, 2];
            state[r, 0] = state[r, 3];
            state[r, 1] = temp;
            state[r, 2] = temp2;
            state[r, 3] = temp3;
            return state;
        }
        public string[,] inverse_shift_rows(string[,] state)
        {
            int r = 1;
            string temp = state[r, 3];
            state[r, 3] = state[r, 2];
            state[r, 2] = state[r, 1];
            state[r, 1] = state[r, 0];
            state[r, 0] = temp;
            r++;
            temp = state[r, 3];
            string temp2 = state[r, 2];
            state[r, 3] = state[r, 1];
            state[r, 2] = state[r, 0];
            state[r, 1] = temp;
            state[r, 0] = temp2;
            r++;
            temp = state[r, 1];
            temp2 = state[r, 2];
            string temp3 = state[r, 3];

            state[r, 3] = state[r, 0];
            state[r, 2] = temp3;
            state[r, 1] = temp2;
            state[r, 0] = temp;
            return state;
        }
        public string[,] MixColumn(string[,] state, Func<string[,]> ConstMatrix)
        {
            string[,] constant = ConstMatrix();
            string[,] result = new string[4, 4];
            for (int k = 0; k < 4; k++)
            {
                for (int i = 0; i < 4; i++)
                {
                    string res = "00000000";
                    for (int j = 0; j < 4; j++)
                    {
                        string temp = GFMultiplier(constant[i, j], state[j, k]);
                        res = xor(temp, res);
                    }
                    result[i, k] = BinToHex(res).PadLeft(2, '0');
                }
            }
            return result;
        }
        public string[,] AddRoundKey(string[,] cipherKey, int Iteration)
        {
            string[,] RCON = new string[4, 10]
            {
                  {  "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36"},

                  {  "00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},

                  {  "00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},

                  {  "00", "00", "00", "00", "00", "00", "00", "00", "00", "00"}

            };
            string[,] sbox = SBOXbuilder();
            string[,] result = new string[4, 4];
            string[] rot = new string[4];

            rot[0] = sbox[convert_to_int(cipherKey[1, 3][0]), convert_to_int(cipherKey[1, 3][1])];
            rot[1] = sbox[convert_to_int(cipherKey[2, 3][0]), convert_to_int(cipherKey[2, 3][1])];
            rot[2] = sbox[convert_to_int(cipherKey[3, 3][0]), convert_to_int(cipherKey[3, 3][1])];
            rot[3] = sbox[convert_to_int(cipherKey[0, 3][0]), convert_to_int(cipherKey[0, 3][1])];
            for (int i = 0; i < 4; i++)
            {
                string temp = "00000000";
                temp = xor(temp, HexToBin(cipherKey[i, 0]));
                temp = xor(temp, HexToBin(rot[i]));
                temp = xor(temp, HexToBin(RCON[i, Iteration]));
                result[i, 0] = BinToHex(temp).PadLeft(2, '0');
            }


            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[j, i] = BinToHex(xor(HexToBin(cipherKey[j, i]), HexToBin(result[j, i - 1]))).PadLeft(2, '0');
                }
            }
            return result;
        }



    }
}
