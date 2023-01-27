using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Collections.Generic;




#if (NETFX_CORE || UWP)
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography.DataProtection;
using Windows.Storage.Streams;
using System.Threading.Tasks;
#else
using System.Security.Cryptography;
#endif 

using System.Text;

namespace Shared
{
    class Crypting
    {
        //Интерфейсы
        public interface ICrypting
        {
            //Дешифрование
            string Decrypt(string ciphertext, string key);

            //Шифрование
            string Encrypt(string plainText, string key);
        }

        public class AES : ICrypting
        {
#if (NETFX_CORE || UWP)

            public string Encrypt(string plainText, string pw)
            {                
                var pwBuffer = CryptographicBuffer.ConvertStringToBinary(pw, BinaryStringEncoding.Utf8);
                var saltBuffer = CryptographicBuffer.ConvertStringToBinary("guid", BinaryStringEncoding.Utf16LE);
                var plainBuffer = CryptographicBuffer.ConvertStringToBinary(plainText, BinaryStringEncoding.Utf16LE);

                // Derive key material for password size 32 bytes for AES256 algorithm
                KeyDerivationAlgorithmProvider keyDerivationProvider = Windows.Security.Cryptography.Core.KeyDerivationAlgorithmProvider.OpenAlgorithm("PBKDF2_SHA1");
                // using salt and 1000 iterations
                KeyDerivationParameters pbkdf2Parms = KeyDerivationParameters.BuildForPbkdf2(saltBuffer, 1000);

                // create a key based on original key and derivation parmaters
                CryptographicKey keyOriginal = keyDerivationProvider.CreateKey(pwBuffer);
                var keyMaterial = CryptographicEngine.DeriveKeyMaterial(keyOriginal, pbkdf2Parms, 32);
                CryptographicKey derivedPwKey = keyDerivationProvider.CreateKey(pwBuffer);

                // derive buffer to be used for encryption salt from derived password key 
                var saltMaterial = CryptographicEngine.DeriveKeyMaterial(derivedPwKey, pbkdf2Parms, 16);

                // display the buffers – because KeyDerivationProvider always gets cleared after each use, they are very similar unforunately
                string keyMaterialString = CryptographicBuffer.EncodeToBase64String(keyMaterial);
                string saltMaterialString = CryptographicBuffer.EncodeToBase64String(saltMaterial);

                SymmetricKeyAlgorithmProvider symProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm("AES_CBC_PKCS7");
                // create symmetric key from derived password key
                CryptographicKey symmKey = symProvider.CreateSymmetricKey(keyMaterial);

                // encrypt data buffer using symmetric key and derived salt material
                var resultBuffer = CryptographicEngine.Encrypt(symmKey, plainBuffer, saltMaterial);
                byte[] result;
                CryptographicBuffer.CopyToByteArray(resultBuffer, out result);

                return Convert.ToBase64String(result);
            }


            public string Decrypt(string encryptedstring, string pw)
            {
                
                var encryptedData = Convert.FromBase64String(encryptedstring);
                var pwBuffer = CryptographicBuffer.ConvertStringToBinary(pw, BinaryStringEncoding.Utf8);
                var saltBuffer = CryptographicBuffer.ConvertStringToBinary("guid", BinaryStringEncoding.Utf16LE);
                var cipherBuffer = CryptographicBuffer.CreateFromByteArray(encryptedData);

                // Derive key material for password size 32 bytes for AES256 algorithm
                KeyDerivationAlgorithmProvider keyDerivationProvider = Windows.Security.Cryptography.Core.KeyDerivationAlgorithmProvider.OpenAlgorithm("PBKDF2_SHA1");
                // using salt and 1000 iterations
                KeyDerivationParameters pbkdf2Parms = KeyDerivationParameters.BuildForPbkdf2(saltBuffer, 1000);

                // create a key based on original key and derivation parmaters
                CryptographicKey keyOriginal = keyDerivationProvider.CreateKey(pwBuffer);
                var keyMaterial = CryptographicEngine.DeriveKeyMaterial(keyOriginal, pbkdf2Parms, 32);
                CryptographicKey derivedPwKey = keyDerivationProvider.CreateKey(pwBuffer);

                // derive buffer to be used for encryption salt from derived password key 
                var saltMaterial = CryptographicEngine.DeriveKeyMaterial(derivedPwKey, pbkdf2Parms, 16);

                // display the keys – because KeyDerivationProvider always gets cleared after each use, they are very similar unforunately
                string keyMaterialString = CryptographicBuffer.EncodeToBase64String(keyMaterial);
                string saltMaterialString = CryptographicBuffer.EncodeToBase64String(saltMaterial);

                SymmetricKeyAlgorithmProvider symProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm("AES_CBC_PKCS7");
                // create symmetric key from derived password material
                CryptographicKey symmKey = symProvider.CreateSymmetricKey(keyMaterial);

                // encrypt data buffer using symmetric key and derived salt material
                var resultBuffer = CryptographicEngine.Decrypt(symmKey, cipherBuffer, saltMaterial);
                string result = CryptographicBuffer.ConvertBinaryToString(BinaryStringEncoding.Utf16LE, resultBuffer);
                return result;
            }

            internal async Task<string> Encrypt(Task<string> plainText, Task<string> pw)
            {
                var key = await pw;
                var text = await plainText;
                return Encrypt((string)text, (string)key);
            }

            internal async Task<string> Decrypt(string plainText, Task<string> pw)
            {
                var key = await pw;
                return Decrypt(plainText, (string)key);
            }

#else

            public string Encrypt(string dataToEncrypt, string password)
            {
                AesManaged aes = null;
                MemoryStream memoryStream = null;
                CryptoStream cryptoStream = null;
                try
                {
                    //Generate a Key based on a Password, Salt and HMACSHA1 pseudo-random number generator 
                    Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(password, Encoding.Unicode.GetBytes("guid"));

                    //Create AES algorithm with 256 bit key and 128-bit block size 
                    aes = new AesManaged();
                    aes.Key = rfc2898.GetBytes(aes.KeySize / 8);
                    rfc2898.Reset(); //needed for WinRT compatibility
                    aes.IV = rfc2898.GetBytes(aes.BlockSize / 8);

                    //Create Memory and Crypto Streams 
                    memoryStream = new MemoryStream();
                    cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

                    //Encrypt Data 
                    byte[] data = Encoding.Unicode.GetBytes(dataToEncrypt);
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();

                    return Convert.ToBase64String(memoryStream.ToArray());

                }
                catch (Exception)
                {
                    return null;
                }
            }

            public string Decrypt(string encryptedstring, string password)
            {
                var dataToDecrypt = Convert.FromBase64String(encryptedstring);
                AesManaged aes = null;
                MemoryStream memoryStream = null;
                CryptoStream cryptoStream = null;
                string decryptedText = "";
                try
                {
                    //Generate a Key based on a Password, Salt and HMACSHA1 pseudo-random number generator 
                    Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(password, Encoding.Unicode.GetBytes("guid"));

                    //Create AES algorithm with 256 bit key and 128-bit block size 
                    aes = new AesManaged();
                    aes.Key = rfc2898.GetBytes(aes.KeySize / 8);
                    rfc2898.Reset(); //neede to be WinRT compatible
                    aes.IV = rfc2898.GetBytes(aes.BlockSize / 8);

                    //Create Memory and Crypto Streams 
                    memoryStream = new MemoryStream();
                    cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write);

                    //Decrypt Data 
                    cryptoStream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
                    cryptoStream.FlushFinalBlock();

                    //Return Decrypted String 
                    byte[] decryptBytes = memoryStream.ToArray();
                    decryptedText = Encoding.Unicode.GetString(decryptBytes, 0, decryptBytes.Length);
                }
                catch (Exception)
                {
                    return null;
                }
                return decryptedText;
            }
#endif

        }

        public class SHA
        {

            //Функции хеширования SHA512

#if (NETFX_CORE || UWP)
            public static string CreateHash(string Password, string Salt)
            {
                HashAlgorithmProvider provider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha512);

                CryptographicHash hash = provider.CreateHash();

                var buffer = CryptographicBuffer.ConvertStringToBinary(string.Concat(Password, Salt), BinaryStringEncoding.Utf8);
                hash.Append(buffer);
                var hashedBuffer = hash.GetValueAndReset();

                return CryptographicBuffer.EncodeToBase64String(hashedBuffer);
            }
#else
            public static string CreateHash(string Password, string Salt)
            {
                var HashTool = new SHA512Managed();
                Byte[] PasswordAsByte = System.Text.Encoding.UTF8.GetBytes(string.Concat(Password, Salt));
                Byte[] EncryptedBytes = HashTool.ComputeHash(PasswordAsByte);
                HashTool.Clear();
                return Convert.ToBase64String(EncryptedBytes);

            }

#endif
        }


        public class RSA : ICrypting
        {
#if (NETFX_CORE || UWP)
            public static Tuple<string, string> CreateKeyPair()
            {
                AsymmetricKeyAlgorithmProvider asym = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaPkcs1);
                CryptographicKey key = asym.CreateKeyPair(2048);
                var privateKeyBuffer = key.Export(CryptographicPrivateKeyBlobType.Capi1PrivateKey);
                var publicKeyBuffer = key.ExportPublicKey(CryptographicPublicKeyBlobType.Capi1PublicKey);
                byte[] privateKeyBytes;
                byte[] publicKeyBytes;
                CryptographicBuffer.CopyToByteArray(privateKeyBuffer, out privateKeyBytes);
                CryptographicBuffer.CopyToByteArray(publicKeyBuffer, out publicKeyBytes);
                string privateKey = Convert.ToBase64String(privateKeyBytes);
                string publicKey = Convert.ToBase64String(publicKeyBytes);
                return new Tuple<string, string>(privateKey, publicKey);
            }




            public string Encrypt(String data, String publicKey)
            {
                var keyBuffer = CryptographicBuffer.DecodeFromBase64String(publicKey);

                AsymmetricKeyAlgorithmProvider asym = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaPkcs1);
                CryptographicKey key = asym.ImportPublicKey(keyBuffer, CryptographicPublicKeyBlobType.Capi1PublicKey);

                var plainBuffer = CryptographicBuffer.ConvertStringToBinary(data, BinaryStringEncoding.Utf8);
                var encryptedBuffer = CryptographicEngine.Encrypt(key, plainBuffer, null);

                byte[] encryptedBytes;
                CryptographicBuffer.CopyToByteArray(encryptedBuffer, out encryptedBytes);

                return Convert.ToBase64String(encryptedBytes);
            }

            public string Decrypt(String data, String privateKey)
            {
                var keyBuffer = CryptographicBuffer.DecodeFromBase64String(privateKey);

                AsymmetricKeyAlgorithmProvider asym = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaPkcs1);
                CryptographicKey key = asym.ImportKeyPair(keyBuffer, CryptographicPrivateKeyBlobType.Capi1PrivateKey);

                var plainBuffer = CryptographicEngine.Decrypt(key, Convert.FromBase64String(data).AsBuffer(), null);

                byte[] plainBytes;
                CryptographicBuffer.CopyToByteArray(plainBuffer, out plainBytes);

                return Encoding.UTF8.GetString(plainBytes, 0, plainBytes.Length);
            }

            public static async Task<string> DecryptUKey(String encryptedString, String ContainerName = null)
            {
                DataProtectionProvider Provider2 = new DataProtectionProvider();
                var bytes = Convert.FromBase64String(encryptedString);
                var data = bytes.AsBuffer();
                IBuffer unprotectedData = await Provider2.UnprotectAsync(data);
                return Encoding.UTF8.GetString(unprotectedData.ToArray(), 0, unprotectedData.ToArray().Length);

            }

            public static async Task<string> EncryptUKey(String openString, String ContainerName = null)
            {
                DataProtectionProvider Provider = new DataProtectionProvider("Local=user");
                byte[] plainBytes = Encoding.UTF8.GetBytes(openString);

                IBuffer data = plainBytes.AsBuffer();


                IBuffer protectedData = await Provider.ProtectAsync(data);
                return Convert.ToBase64String(protectedData.ToArray());

            }






#else
            /// <summary>
            ///
            /// </summary>
            /// <returns>PrivateKey; PublicKey</returns>
            /// 
#if ANDROID
            public static Tuple<string, string> CreateKeyPair()
            {
                var cspParams = new CspParameters { ProviderType = 1 /* PROV_RSA_FULL */ };

                var rsaProvider = new RSACryptoServiceProvider(512, cspParams);

                string publicKey = Convert.ToBase64String(rsaProvider.ExportCspBlob(false));
                string privateKey = Convert.ToBase64String(rsaProvider.ExportCspBlob(true));

                return new Tuple<string, string>(privateKey, publicKey);
            }
            internal static Tuple<string, string> CreateKeyPair(int v)
            {
                var cspParams = new CspParameters { ProviderType = 1 /* PROV_RSA_FULL */ };

                var rsaProvider = new RSACryptoServiceProvider(v, cspParams);

                string publicKey = Convert.ToBase64String(rsaProvider.ExportCspBlob(false));
                string privateKey = Convert.ToBase64String(rsaProvider.ExportCspBlob(true));

                return new Tuple<string, string>(privateKey, publicKey);
            }
#else
            public static Tuple<string, string> CreateKeyPair()
            {
                var cspParams = new CspParameters { ProviderType = 1 /* PROV_RSA_FULL */ };

                var rsaProvider = new RSACryptoServiceProvider(2048, cspParams);

                string publicKey = Convert.ToBase64String(rsaProvider.ExportCspBlob(false));
                string privateKey = Convert.ToBase64String(rsaProvider.ExportCspBlob(true));

                return new Tuple<string, string>(privateKey, publicKey);
            }
#endif


            public static string CreateUserKeyPair(string ContainerName, int keySize)
            {
                CspParameters cp = new CspParameters { ProviderType = 1 /* PROV_RSA_FULL */ };
                cp.KeyContainerName = ContainerName;
                cp.Flags = CspProviderFlags.NoPrompt | CspProviderFlags.UseDefaultKeyContainer | CspProviderFlags.UseNonExportableKey;
                cp.KeyNumber = (int)KeyNumber.Exchange;

                string uniqueContainerName = string.Empty;

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize, cp))
                {
                    rsa.PersistKeyInCsp = true;

                    uniqueContainerName = rsa.CspKeyContainerInfo.UniqueKeyContainerName;
                }

                return uniqueContainerName;
            }

            public static string PublicKey(string ContainerName)
            {
                CspParameters cp = new CspParameters { ProviderType = 1 /* PROV_RSA_FULL */ };
                cp.KeyContainerName = ContainerName;
                cp.Flags = CspProviderFlags.UseDefaultKeyContainer;

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cp);

                return Convert.ToBase64String(rsa.ExportCspBlob(false));
            }


            public string Encrypt(String data, String publicKey)
            {
                var cspParams = new CspParameters { ProviderType = 1 /* PROV_RSA_FULL */ };
                var rsaProvider = new RSACryptoServiceProvider(cspParams);

                rsaProvider.ImportCspBlob(Convert.FromBase64String(publicKey));

                byte[] plainBytes = Encoding.UTF8.GetBytes(data);
                byte[] encryptedBytes = rsaProvider.Encrypt(plainBytes, false);

                return Convert.ToBase64String(encryptedBytes);
            }

            public string Decrypt(String encryptedString, String privateKey)
            {
                var cspParams = new CspParameters { ProviderType = 1 /* PROV_RSA_FULL */ };
                var rsaProvider = new RSACryptoServiceProvider(cspParams);

                rsaProvider.ImportCspBlob(Convert.FromBase64String(privateKey));

                byte[] plainBytes = rsaProvider.Decrypt(Convert.FromBase64String(encryptedString), false);

                string plainText = Encoding.UTF8.GetString(plainBytes, 0, plainBytes.Length);

                return plainText;
            }

            public static string DecryptUKey(String encryptedString, String ContainerName)
            {
                CspParameters cspParams = new CspParameters();
                cspParams.KeyContainerName = ContainerName;
                cspParams.Flags = CspProviderFlags.UseDefaultKeyContainer;

                RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(cspParams);

                byte[] plainBytes = rsaProvider.Decrypt(Convert.FromBase64String(encryptedString), false);

                string plainText = Encoding.UTF8.GetString(plainBytes, 0, plainBytes.Length);

                return plainText;
            }

            public static string EncryptUKey(String encryptedString, String ContainerName)
            {
                CspParameters cspParams = new CspParameters();
                cspParams.KeyContainerName = ContainerName;
                cspParams.Flags = CspProviderFlags.UseDefaultKeyContainer;

                RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(cspParams);

                byte[] plainBytes = Encoding.UTF8.GetBytes(encryptedString);
                byte[] encryptedBytes = rsaProvider.Encrypt(plainBytes, false);

                return Convert.ToBase64String(encryptedBytes);
            }


#endif
        }

        public static string GeneratePassword(int length, bool pin = false)
        {
            if (pin)
            {
                const string PossibleSymbols = "0123456789";
                return GetRandomString(length, PossibleSymbols);
            }
            else
            {
                const string PossibleSymbols =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                "abcdefghijklmnopqrstuvwxyz" +
                "0123456789";
                return GetRandomString(length, PossibleSymbols);

            }

        }



        private static string GetRandomString(int length, IEnumerable<char> characterSet)
        {
            if (length < 0)
                throw new ArgumentException("length must not be negative", "length");
            if (length > int.MaxValue / 8) // 250 million chars ought to be enough for anybody
                throw new ArgumentException("length is too big", "length");
            if (characterSet == null)
                throw new ArgumentNullException("characterSet");
            var characterArray = characterSet.Distinct().ToArray();
            if (characterArray.Length == 0)
                throw new ArgumentException("characterSet must not be empty", "characterSet");

            var bytes = new byte[length * 8];
#if (NETFX_CORE || UWP)
            // Create a buffer from the byte array.
            var buffLength = length*8;
            var buffRnd = CryptographicBuffer.GenerateRandom((uint)buffLength);
            String strRndData = CryptographicBuffer.EncodeToBase64String(buffRnd);
            bytes=Convert.FromBase64String(strRndData);
#else
            new RNGCryptoServiceProvider().GetBytes(bytes);
#endif

            var result = new char[length];
            for (int i = 0; i < length; i++)
            {
                ulong value = BitConverter.ToUInt64(bytes, i * 8);
                result[i] = characterArray[value % (uint)characterArray.Length];
            }
            return new string(result);
        }


    }

}
