using Newtonsoft.Json;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace Program
{
        //Taisymas solid panaikinti static metodus 
    //Single Responsibility Principle (SRP) viena klase vienas darbas  // THERE IS
    //Open/Closed Principle (OCP) gali buti praplesta ir modifikuota  // THERE IS
    //Liskov Substitution Principle (LSP) turi buti galima pakeisti viena klase kita // THERE IS
    //Interface Segregation Principle (ISP) nereikalingu metodu nenaudojimas // Istrinta
    //The Dependency Inversion Principle(DIP) is one of the SOLID principles of object-oriented design. // THERE IS
    public class PasswordManager
    {
        private string username = string.Empty; // Encapsulation
        private string passwordHash = string.Empty; // Encapsulation
        private Random random; // Dependency inversion (Random created inside, but could be injected)
        private SerializationBase serializer; // Abstraction: Serializer is defined via an abstract base
        private EncryptionBase encryptor; // Abstraction: Encryptor is defined via an abstract base

        public PasswordManager()
        {
            random = new Random(); // Dependency Inversion: internal management of dependency
            serializer = new JSONSerializer(); // Abstraction, adheres to Open/Closed Principle (OCP)
            encryptor = new AES(); // Abstraction, OCP
        }

        public void Run()
        {
            // Dependency Injection for encryptor choice: Strategy Pattern
            while (true)
            {
                Console.Clear();
                Console.WriteLine("Select encryption method:\n1. AES\n2. RSA");
                if (!int.TryParse(Console.ReadLine(), out int encryptionChoice) || (encryptionChoice != 1 && encryptionChoice != 2))
                {
                    Console.WriteLine("Invalid choice. Defaulting to AES.");
                    encryptionChoice = 1;
                }

                encryptor = encryptionChoice == 1 ? new AES() : new RSAEncryption();

                Console.WriteLine("What do you want to do?\n1. Login\n2. Register\n0. Quit");
                if (!int.TryParse(Console.ReadLine(), out int operation) || operation < 0 || operation > 2)
                {
                    Console.WriteLine("Invalid operation. Try again.");
                    continue;
                }

                if (operation == 0) return;

                Console.Write("Enter your username: ");
                username = Console.ReadLine() ?? string.Empty;

                Console.Write("Enter your password: ");
                string password = Console.ReadLine() ?? string.Empty;

                string path = username + ".txt";

                switch (operation)
                {
                    case 1:
                        Login(path, password);
                        break;

                    case 2:
                        Register(path, password);
                        break;
                }
            }
        }

        private void Login(string path, string password)
        {
            if (File.Exists(path))
            {
                // --- Secure password hashing and verification (Encapsulation & Abstraction) ---
                HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
                byte[] passwordPbkdf2 = Rfc2898DeriveBytes.Pbkdf2(password, Encoding.ASCII.GetBytes(username), 1000, hashAlgorithm, 32);
                passwordHash = Convert.ToBase64String(passwordPbkdf2);

                string decryptedPasswordHash = encryptor.DecryptFile(path, passwordHash);
                if (!string.IsNullOrEmpty(decryptedPasswordHash))
                {
                    PasswordMenu(path);
                }
                else
                {
                    Console.WriteLine("Invalid password. Try again.");
                }
            }
            else
            {
                Console.WriteLine("User does not exist! Try again.");
            }
        }

        private void Register(string path, string password)
        {
            if (File.Exists(path))
            {
                Console.WriteLine("User already exists! Try logging in.");
                return;
            }

            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
            byte[] passwordPbkdf2 = Rfc2898DeriveBytes.Pbkdf2(password, Encoding.ASCII.GetBytes(username), 1000, hashAlgorithm, 32);
            passwordHash = Convert.ToBase64String(passwordPbkdf2);

            string serializedData = serializer.Serialize(new List<Account>()); // Abstraction
            encryptor.EncryptFile(serializedData, passwordHash, path); // Polymorphism in action


            PasswordMenu(path);
        }

        private void PasswordMenu(string path)
        {
            // --- Dependency Injection (for serialization, encryption) ---
            var table = new Table(1, 4)
            {
                data = new string[1, 4]
                {
                    { "Username", "Password", "Used in", "Description" }
                }
            };

            string decryptedData = encryptor.DecryptFile(path, passwordHash); // Polymorphism
            var data = serializer.Deserialize<List<Account>>(decryptedData); // Polymorphism

            foreach (var account in data)
            {
                table.AddRow();
                var cols = account.ToCols(); // Encapsulation
                table.data[data.IndexOf(account) + 1, 0] = cols[0];
                table.data[data.IndexOf(account) + 1, 1] = cols[1];
                table.data[data.IndexOf(account) + 1, 2] = cols[2];
                table.data[data.IndexOf(account) + 1, 3] = cols[3];
            }

            table.DrawTable(); // Encapsulation: Table class handles its own behavior.

            while (true)
            {
                Console.WriteLine("Choose your operation: 1. Add new account 2. Find password 3. Change password 4. Delete account 0. Logout");
                if (!int.TryParse(Console.ReadLine(), out int operation) || operation < 0 || operation > 4)
                {
                    Console.WriteLine("Invalid operation. Try again.");
                    continue;
                }

                if (operation == 0) break;

                HandleMenuOperation(operation, data, table);
            }

            string serializedData = serializer.Serialize(data); // Polymorphism for serialization
            encryptor.EncryptFile(serializedData, passwordHash, path); // Polymorphism for encryption
        }

        private void HandleMenuOperation(int operation, List<Account> data, Table table)
        {
            switch (operation)
            {
                case 1:
                    AddNewAccount(data, table); // Encapsulation
                    break;

                case 2:
                    FindPassword(data); // Encapsulation
                    break;

                case 3:
                    ChangePassword(data, table); // Encapsulation
                    break;

                case 4:
                    DeleteAccount(data, table); // Encapsulation
                    break;
            }
        }

        private void AddNewAccount(List<Account> data, Table table)
        {
            Console.Write("Enter username: ");
            string _username = Console.ReadLine() ?? string.Empty;

            Console.Write("Enter password: ");
            string _password = Console.ReadLine() ?? string.Empty;

            Console.Write("Enter place of use: ");
            string _usedIn = Console.ReadLine() ?? string.Empty;

            Console.Write("Enter description: ");
            string _description = Console.ReadLine() ?? string.Empty;

            var account = new Account(_username, _password, _usedIn, _description);
            data.Add(account);

            table.AddRow();
            var cols = account.ToCols();
            table.data[data.IndexOf(account) + 1, 0] = cols[0];
            table.data[data.IndexOf(account) + 1, 1] = cols[1];
            table.data[data.IndexOf(account) + 1, 2] = cols[2];
            table.data[data.IndexOf(account) + 1, 3] = cols[3];
            table.DrawTable();
        }

        private void FindPassword(List<Account> data)
        {
            Console.Write("Enter username: ");
            string _username = Console.ReadLine() ?? string.Empty;

            var acc = data.FirstOrDefault(a => a.Username == _username);
            Console.Clear();

            if (acc == null)
            {
                Console.WriteLine("Password not found! Press any key to continue.");
                Console.ReadKey();
            }
            else // table padaryta kad sutiktu be static funkciju
            {
                var table = new Table(2, 4);
                table.data = new string[2, 4];
                table.data[0, 0] = "Username";
                table.data[0, 1] = "Password";
                table.data[0, 2] = "Used in";
                table.data[0, 3] = "Description";

                var cols = acc.ToCols();
                for (int i = 0; i < cols.Length; i++)
                {
                    table.data[1, i] = cols[i];
                }
                table.DrawTable();
                Console.ReadKey();
            }
        }

        private void ChangePassword(List<Account> data, Table table)
        {
            Console.Write("Enter username: ");
            string _username = Console.ReadLine() ?? string.Empty;

            var acc = data.FirstOrDefault(a => a.Username == _username);
            if (acc == null)
            {
                Console.WriteLine("Account not found. Press any key to continue.");
                Console.ReadKey();
                return;
            }

            Console.WriteLine("Enter new password (leave empty to generate password):");
            string newPassword = Console.ReadLine() ?? string.Empty;
            if (string.IsNullOrEmpty(newPassword))
            {
                newPassword = GeneratePassword(10);
                Console.WriteLine($"Generated Password: {newPassword}");
            }

            acc.ChangePassword(newPassword);// SRP: Table's own behavior encapsulated.
            var cols = acc.ToCols();
            table.data[data.IndexOf(acc) + 1, 0] = cols[0];
            table.data[data.IndexOf(acc) + 1, 1] = cols[1];
            table.data[data.IndexOf(acc) + 1, 2] = cols[2];
            table.data[data.IndexOf(acc) + 1, 3] = cols[3];
            table.DrawTable();
        }

        private void DeleteAccount(List<Account> data, Table table)
        {
            Console.Write("Enter username: ");
            string _username = Console.ReadLine() ?? string.Empty;

            var acc = data.FirstOrDefault(a => a.Username == _username);
            if (acc == null)
            {
                Console.WriteLine("Account not found. Press any key to continue.");
                Console.ReadKey();
                return;
            }

            table.DeleteRow(data.IndexOf(acc) + 1);
            data.Remove(acc);
            table.DrawTable();
        }

        public string GeneratePassword(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
            var passwordBuilder = new StringBuilder(length);

            for (int i = 0; i < length; i++)
                passwordBuilder.Append(chars[random.Next(chars.Length)]);

            return passwordBuilder.ToString();
        }
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            PasswordManager manager = new();
            manager.Run();
        }
    }

    // --- Abstraction Example ---
    // EncryptionBase and SerializationBase are abstract classes implemented by AES, RSAEncryption, and JSONSerializer.

    public abstract class EncryptionBase
    {
        public abstract void EncryptFile(string data, string key, string path);
        public abstract string DecryptFile(string path, string key);
    }

    //Inheritance
    //Definition: Inheritance is a mechanism where a class (child) derives properties and behavior from another class (parent).
    // AES encryption implementation (Inheritance)
    // AES and RSAEncryption classes inherit from EncryptionBase, and JSONSerializer inherits from SerializationBase
    /*
     Advanced Encryption Standard (AES) is a specification for the encryption
     Each round comprises of 4 steps :
     SubBytes
     ShiftRows
     MixColumns
     Add Round Key
     */
    public class AES : EncryptionBase
    {
        public override void EncryptFile(string data, string key, string path)
        {
            byte[] convertedKey = Convert.FromBase64String(key);
            byte[]? encrypted = EncryptString(data, convertedKey);

            if (encrypted == null)
                return;

            File.WriteAllBytes(path, encrypted);
        }

        public override string DecryptFile(string path, string key)
        {
            if (!File.Exists(path))
                return string.Empty;

            byte[] encrypted = File.ReadAllBytes(path);
            byte[] bytes = Convert.FromBase64String(key);

            string? data = DecryptString(encrypted, bytes);

            return data ?? string.Empty;
        }

        private byte[]? EncryptString(string data, byte[] key)
        {
            if (string.IsNullOrEmpty(data) || key.Length != 32)
                return null;

            byte[] encrypted;
            byte[] IV;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.GenerateIV();
                IV = aesAlg.IV;

                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new())
                {
                    using (CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new(csEncrypt))
                        {
                            swEncrypt.Write(data);
                        }
                    }

                    encrypted = msEncrypt.ToArray();
                }
            }

            byte[] result = new byte[IV.Length + encrypted.Length];

            IV.CopyTo(result, 0);
            encrypted.CopyTo(result, IV.Length);

            return result;
        }

        private string? DecryptString(byte[] cipherText, byte[] Key)
        {
            if (cipherText.Length <= 0 || Key.Length != 32)
                return null;

            byte[] IV = new byte[16];
            byte[] cipher = new byte[cipherText.Length - 16];

            Array.Copy(cipherText, 0, IV, 0, 16);
            Array.Copy(cipherText, 16, cipher, 0, cipherText.Length - 16);

            string? plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new(cipher))
                {
                    using (CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
    public class RSAEncryption : EncryptionBase
    {
        private static RSAParameters _publicKey;
        private static RSAParameters _privateKey;

        public RSAEncryption()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                _publicKey = rsa.ExportParameters(false);
                _privateKey = rsa.ExportParameters(true);
            }
        }

        public override void EncryptFile(string data, string key, string path)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(_publicKey);
                var encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(data), false);
                File.WriteAllBytes(path, encryptedData);
            }
        }

        public override string DecryptFile(string path, string key)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(_privateKey);
                var encryptedData = File.ReadAllBytes(path);
                var decryptedData = rsa.Decrypt(encryptedData, false);
                return Encoding.UTF8.GetString(decryptedData);
            }
        }
    }

    // Abstract base class for serialization (Abstraction)
    public abstract class SerializationBase
    {
        public abstract string Serialize<T>(T obj);
        public abstract T Deserialize<T>(string json);
    }

    // JSON serialization implementation (Inheritance)
    public class JSONSerializer : SerializationBase
    {
        public override string Serialize<T>(T obj)
        {
            return JsonConvert.SerializeObject(obj, Formatting.Indented);
        }

        public override T Deserialize<T>(string json)
        {
            return JsonConvert.DeserializeObject<T>(json) ?? throw new InvalidOperationException("Deserialization failed.");
        }
    }

    public class Table
    {
        private int columns, rows;

        public string[,] data;
        private int[] columnWidths;

        public Table(int _rows, int _cols)
        {
            columns = _cols;
            rows = _rows;

            data = new string[rows, columns];

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    data[i, j] = "No data";
                }
            }

            DrawTable();
        }

        public void AddRow()
        {
            var temp = data;

            data = new string[++rows, columns];

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    data[i, j] = i < rows - 1 ? temp[i, j] : "No data";
                }
            }

            DrawTable();
        }

        public void DeleteRow(int rowIndex)
        {
            if (rowIndex < 0 || rowIndex >= rows)
            {
                Console.WriteLine("Invalid row index.");
                return;
            }

            var temp = data;

            data = new string[--rows, columns];

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    int r = i;

                    if (i >= rowIndex)
                        r++;

                    data[i, j] = temp[r, j];
                }
            }

            DrawTable();
        }

        private void CalculateColumnWidths()
        {
            columnWidths = new int[columns];

            // Calculate the maximum width for each column
            for (int j = 0; j < columns; j++)
            {
                int maxWidth = 0;
                for (int i = 0; i < rows; i++)
                {
                    if (data[i, j].Length > maxWidth)
                        maxWidth = data[i, j].Length;
                }
                columnWidths[j] = maxWidth;
            }
        }

        public void DrawTable()
        {
            Console.Clear();

            CalculateColumnWidths();

            // Draw the table header
            Console.WriteLine("Passwords");
            Console.WriteLine(new string('-', columnWidths.Sum() + columns * 3 - 1));

            // Draw the table rows
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    Console.Write($"{data[i, j].PadRight(columnWidths[j] + 2)}");
                }
                Console.WriteLine();
            }

            Console.SetCursorPosition(0, rows + 2);
        }
    }
    // Class representing an account (Encapsulation)
    //Encapsulation
    /*Definition: Encapsulation means bundling data(fields) and methods that operate on the data into a single unit(class). 
    Access to the data is restricted using access modifiers(private, public, etc.).
    Examples in Code:
    The Account class encapsulates account details(e.g., Username, Password, UsedIn, Description) and provides controlled access via properties and methods like ChangePassword.*/
    public class Account
    {
        public string Username { get; private set; }
        public string Password { get; private set; }
        public string UsedIn { get; private set; }
        public string Description { get; private set; }

        public Account(string username, string password, string usedIn, string description)
        {
            Username = username;
            Password = password;
            UsedIn = usedIn;
            Description = description;
        }

        public void ChangePassword(string newPassword) => Password = newPassword;

        public string[] ToCols() => new string[4] { Username, Password, UsedIn, Description };
    }
}
