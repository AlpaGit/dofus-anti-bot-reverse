Les champs **cvld**, **cvle**, **cvlf**

```cs
  _cvld = new BigInteger(DHStandardGroups.rfc2409_768.P.ToByteArray());
  _cvle = new BigInteger(DHStandardGroups.rfc2409_768.Q.ToByteArray());
  _cvlf = new BigInteger(DHStandardGroups.rfc2409_768.G.ToByteArray());
```

1) Le serveur envois un **ServerVerificationEvent**
2) Le client génère un **cvlg** avec :
```cs
  var secureRandom = new SecureRandom(); // Instance shared sur tout les random
  var buffer = new byte[0x400]; // ( 1024 bytes )
  secureRandom.NextBytes(buffer); // On fill le buffer avec des données random
  var tmp = new BigInteger(buffer, true, false); // Unsigned
  var cvlg = tmp % cvld;
```

En suite le client génère un **cvlh** avec simplement un
```cs
  var buffer = new byte[50];
  secureRandom.NextBytes(buffer); // On fill le buffer avec des données random
  var cvlh = new BigInteger(buffer, true, false); // Unsigned
```

La property ChallengeKey de **ClientChallengeInitRequest** représente le résultat de 
```cs
var challengeKey = BigInteger.ModPow(cvlf, cvlh, cvld);
```
3) Le serveur renvoi un ServerChallengeEvent() avec ou non une property **Value**
4) Déjà on recupère le **UniqueDeviceId**
```cs
string GetWmiProperty(string wmiClass, string property)
{
    var searcher = new ManagementObjectSearcher("SELECT " + property + " FROM " + wmiClass);
    foreach (var obj in searcher.Get())
    {
        return (string)obj.Properties[property].Value ?? string.Empty;
    }
    
    return string.Empty;
}

var serialNumber = GetWmiProperty("Win32_BaseBoard", "SerialNumber");
var biosSerialNumber = GetWmiProperty("Win32_BIOS", "SerialNumber");
var osSerialNumber = GetWmiProperty("Win32_OperatingSystem", "SerialNumber");

var hwidUnencrypted = serialNumber + biosSerialNumber  + osSerialNumber;
var sha1 = System.Security.Cryptography.SHA1.Create();
var hwid = string.Join("", sha1.ComputeHash(Encoding.UTF8.GetBytes(hwidUnencrypted)).Select(b => b.ToString("x2")));

var strBuilder = new StringBuilder();
strBuilder.Append(hwid);

var allNetworkInterfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
// faut faire gaffe et peut être limité a 4 max, sur Unity et sur dotnet 9 j'ai pas le même nombre qui ressort (5 sur Unity et 49 sur dotnet9)
foreach (var i in allNetworkInterfaces) 
{
    strBuilder.Append(i.GetPhysicalAddress());
}

var sha256 = System.Security.Cryptography.SHA256.Create();
var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(strBuilder.ToString()));
var uniqueDeviceId = BitConverter.ToString(hash).Replace("-", "");
```

Si **Value** du packet n'est pas spécifié : 

```cs
var b1 = BigInteger.ModPow(cvlf, cvlg, cvld);
var b2 = BigInteger.ModPow(cvlf, cvlh, cvld);

var str1 = cvlf.ToString();
var str2 = b1.ToString();
var str3 = b2.ToString();

var conct = string.Concat(str1, str2, str3, uniqueDeviceId);
var bytes = Encoding.UTF8.GetBytes(conct);

// Sha256Digest
var sha256 = new Sha256Digest();
sha256.BlockUpdate(bytes, 0, bytes.Length);
var digestSize = sha256.GetDigestSize();
var output = new byte[digestSize];
sha256.DoFinal(output, 0);

// Array reverse
var outputReversed = Org.BouncyCastle.Utilities.Arrays.Reverse(output);
var o = new BigInteger(outputReversed, true, false);
var m = BigInteger.Multiply(o, cvlg);
var a = BigInteger.Add(cvlh, m);

var v56 = a % cvle;
if (v56.Sign < 0)
{
    v56 += cvle;
}

var proof = v56.ToString();
```

Dans le cas où la **Value** est spécificié on a pas besoin de tout ça, juste :

```cs
var bigBuffer = message.Value; // On store la value du packet ici
var bigBufferInt = BigInteger.Parse(bigBuffer);
var cv = BigInteger.Multiply(bigBufferInt, cvlg);
var l = BigInteger.Add(cvlh, cv);
var f = l % cvle;

if (f.Sign < 0)
{
    f += cvle;
}

var proof = f.ToString();
```

Et voilà ! On renvoi le dernier ClientChallengeProofRequest avec la property **Proof** et c'est win
