using System.Text;
using System.Security.Cryptography;
namespace ch3_hashing_and_salting_passwords;
class Program
{
    static void Main(string[] args)
    {
        var name = "Omar";

        var encryptedName = EncryptData(name);

        Console.WriteLine(encryptedName);

        if (ValidateEncryptedData(name, encryptedName))
        {
            Console.WriteLine($"The {nameof(name)} entered is correct.");
        }
        else
        {
            Console.WriteLine($"The {nameof(name)} entered is not correct.");
        }
    }

    private static bool ValidateEncryptedData(string valueToValidate, string valueFromDataBase)
    {
        var arrValues = valueFromDataBase.Split(':');
        var encryptedValue = arrValues[0];
        var salt = arrValues[1];
        var saltedValue = Encoding.UTF8.GetBytes(salt + valueToValidate);
        var hash = SHA256.HashData(saltedValue);
        var enteredValueToValidate = Convert.ToBase64String(hash);

        return encryptedValue.Equals(enteredValueToValidate);
    }

    private static string EncryptData(string valueToEncrypt)
    {
        string GenerateSalt()
        {
            var salt = new byte[32];
            var generator = RandomNumberGenerator.Create();
            generator.GetBytes(salt);

            return Convert.ToBase64String(salt);
        }

        string EncryptValue(string strValue)
        {
            var saltValue = GenerateSalt();
            var saltedPassword = Encoding.UTF8.GetBytes(saltValue + strValue);

            var hash = SHA256.HashData(saltedPassword);

            return $"{Convert.ToBase64String(hash)}:{saltValue}";
        }

        return EncryptValue(valueToEncrypt);
    }
}
