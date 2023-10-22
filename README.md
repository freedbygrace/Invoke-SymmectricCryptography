# Invoke-SymmectricCryptography

## SYNOPSIS
Performs value encryption or decryption using a specified algorithm.

## SYNTAX

### Encryption (Default)
```
Invoke-SymmectricCryptography [-Encrypt] -Algorithm <String> -Data <String[]> [-Export] [-ExportFormat <String>] [-ExportPath <FileInfo>] [-ContinueOnError] [<CommonParameters>]
```

### Decryption
```
Invoke-SymmectricCryptography [-Decrypt] -Algorithm <String> -EncryptedData <String> -Key <String> -InitializationVector <String> [-ContinueOnError] [<CommonParameters>]
```

## DESCRIPTION
A random key and initialization vector (IV) will be generated with each execution for maximum security.

This means that the resulting encrypted data will NEVER be the same, even if the value to be encrypted is!

This function is great for encrypting data that will NOT be transmitted over a network.
In other words, data at rest.

If transmitting the data over a network is required, consider breaking the encrypted data, key, and initialization vector apart.

## EXAMPLES

### EXAMPLE 1
```
$EncryptionResult = Invoke-SymmectricCryptography -Encrypt -Algorithm AES -Data 'SomeValueRequiringEncryption'

Write-Output -InputObject ($EncryptionResult)
```
### EXAMPLE 2
```
$DecryptionResult = Invoke-SymmectricCryptography -Decrypt -Algorithm AES -Data 'msDFP5hUQo8flkb+qnRSl+1yEaKEhl5Lr3LBfClXSMY=' -Key 'oc5cuCuOhw1qJvwr1iwHr9mOWXmLTMCgw1zlIOZDf78=' -InitializationVector 'zDpcPE2a4YWF/gFmGQoZhQ=='

Write-Output -InputObject ($DecryptionResult)
```
### EXAMPLE 3
```
$InvokeSymmectricCryptographyParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'

$InvokeSymmectricCryptographyParameters.Encrypt = $True
 $InvokeSymmectricCryptographyParameters.Algorithm = 'AES'
 $InvokeSymmectricCryptographyParameters.Data = New-Object -TypeName 'System.Collections.Generic.List\[System.String\]'
    $InvokeSymmectricCryptographyParameters.Data.Add("AValueThatNeedsToBeEncrypted")
    $InvokeSymmectricCryptographyParameters.Data.Add("AnotherValueThatNeedsToBeEncrypted")
 $InvokeSymmectricCryptographyParameters.Export = $True
 $InvokeSymmectricCryptographyParameters.ExportFormat = 'XML'
 $InvokeSymmectricCryptographyParameters.ExportPath = "$($Env:UserProfile)\Downloads\EncryptedData.xml"
 $InvokeSymmectricCryptographyParameters.ContinueOnError = $False
 $InvokeSymmectricCryptographyParameters.Verbose = $True

$EncryptionResult = Invoke-SymmectricCryptography @InvokeSymmectricCryptographyParameters

Write-Output -InputObject ($EncryptionResult)
```
### EXAMPLE 4
```
$InvokeSymmectricCryptographyParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'

$InvokeSymmectricCryptographyParameters.Decrypt = $True
 $InvokeSymmectricCryptographyParameters.Algorithm = 'AES'
 $InvokeSymmectricCryptographyParameters.EncryptedData = 'msDFP5hUQo8flkb+qnRSl+1yEaKEhl5Lr3LBfClXSMY='
 $InvokeSymmectricCryptographyParameters.Key = 'oc5cuCuOhw1qJvwr1iwHr9mOWXmLTMCgw1zlIOZDf78='
 $InvokeSymmectricCryptographyParameters.InitializationVector = 'zDpcPE2a4YWF/gFmGQoZhQ=='
 $InvokeSymmectricCryptographyParameters.ContinueOnError = $False
 $InvokeSymmectricCryptographyParameters.Verbose = $True

$DecryptionResult = Invoke-SymmectricCryptography @InvokeSymmectricCryptographyParameters

Write-Output -InputObject ($DecryptionResult)
```
### EXAMPLE 5
```
$InvokeSymmectricCryptographyParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'

$InvokeSymmectricCryptographyParameters.Encrypt = $True
 $InvokeSymmectricCryptographyParameters.Algorithm = 'AES'
 $InvokeSymmectricCryptographyParameters.Data = "AValueThatNeedsToBeEncrypted"
 $InvokeSymmectricCryptographyParameters.ContinueOnError = $False
 $InvokeSymmectricCryptographyParameters.Verbose = $True

$EncryptionResult = Invoke-SymmectricCryptography @InvokeSymmectricCryptographyParameters

Write-Output -InputObject ($EncryptionResult)

$InvokeSymmectricCryptographyParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
 $InvokeSymmectricCryptographyParameters.Decrypt = $True
 $InvokeSymmectricCryptographyParameters.Algorithm = $EncryptionResult.Algorithm
 $InvokeSymmectricCryptographyParameters.EncryptedData = $EncryptionResult.Data
 $InvokeSymmectricCryptographyParameters.Key = $EncryptionResult.Key
 $InvokeSymmectricCryptographyParameters.InitializationVector = $EncryptionResult.InitializationVector
 $InvokeSymmectricCryptographyParameters.ContinueOnError = $False
 $InvokeSymmectricCryptographyParameters.Verbose = $True

$DecryptionResult = Invoke-SymmectricCryptography @InvokeSymmectricCryptographyParameters

Write-Output -InputObject ($DecryptionResult)
```
## PARAMETERS

### -Algorithm
Specifies the algorithm used for encryption or decryption.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ContinueOnError
Specifies that errors will be logged as warnings, but not considered fatal.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Data
Specifies the original string value that will be encrypted.

```yaml
Type: System.String[]
Parameter Sets: Encryption
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Decrypt
Specifies that decryption will be performed.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: Decryption
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Encrypt
Specifies that encryption will be performed.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: Encryption
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -EncryptedData
Specifies the previously encrypted string value that will be decrypted.

```yaml
Type: System.String
Parameter Sets: Decryption
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Export
Specifies that the encrypted data is to be exported.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: Encryption
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportFormat
Specifies the format that the encrypted data will be exported in.

```yaml
Type: System.String
Parameter Sets: Encryption
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportPath
Specifies the path that the encrypted data will be exported to.

```yaml
Type: System.IO.FileInfo
Parameter Sets: Encryption
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InitializationVector
Specifies the initialization vector (IV) that is required for decryption.

```yaml
Type: System.String
Parameter Sets: Decryption
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Key
Specifies the decryption key that is required for decryption.

```yaml
Type: System.String
Parameter Sets: Decryption
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### System.Management.Automation.PSObject
## NOTES
Any useful tidbits

## RELATED LINKS

[https://codeandkeep.com/PowerShell-Aes-Encryption/](https://codeandkeep.com/PowerShell-Aes-Encryption/)

[https://smsagent.blog/2022/09/23/encrypting-sensitive-data-for-transit-or-rest-with-powershell/](https://smsagent.blog/2022/09/23/encrypting-sensitive-data-for-transit-or-rest-with-powershell/)

[https://stackoverflow.com/questions/67883498/powershell-password-encryption-decryption-with-key](https://stackoverflow.com/questions/67883498/powershell-password-encryption-decryption-with-key)

[https://medium.com/@sumindaniro/encrypt-decrypt-data-with-powershell-4a1316a0834b](https://medium.com/@sumindaniro/encrypt-decrypt-data-with-powershell-4a1316a0834b)

## SAMPLE OUTPUT:

```
Algorithm                 : AES
CryptoServiceProvider     : System.Security.Cryptography.AESCryptoServiceProvider
CryptoServiceProviderName : AESCryptoServiceProvider
EncryptedDataObjectList   : {@{Algorithm=AES; EncryptedData=IGHYeiv2xgIx5bk3JtZvvgsex2p4KV3TL4GGDs9jfzY=; Key=Jpt2nyeCOfxDZb2UuzM92DCrBAhLiv1gXoASo2zOfL4=; 
                            InitializationVector=SOpUqOH6CRvhtF40eM8Cng==; 
                            DKIV=IGHYeiv2xgIx5bk3JtZvvgsex2p4KV3TL4GGDs9jfzY=:Jpt2nyeCOfxDZb2UuzM92DCrBAhLiv1gXoASo2zOfL4=:SOpUqOH6CRvhtF40eM8Cng==}, @{Algorithm=AES; 
                            EncryptedData=gulf1oID8ueF0SgrziYCF8VDHmKNJUCg+CgolgVHE2acMvFQYL26OvaSww83lxSI; Key=3LZn9vQWAonvhSSavNectgiBex9goOFI/Nq6Wht16ao=; 
                            InitializationVector=SkQewVlEyy5Qp1O6yOWH9A==; 
                            DKIV=gulf1oID8ueF0SgrziYCF8VDHmKNJUCg+CgolgVHE2acMvFQYL26OvaSww83lxSI:3LZn9vQWAonvhSSavNectgiBex9goOFI/Nq6Wht16ao=:SkQewVlEyy5Qp1O6yOWH9A==}}
ExportFormat              : XML
ExportContent             : <?xml version="1.0" encoding="utf-8"?>
                            
                            <Settings>
                            	<Metadata>
                            		<GeneratedDate>2023-10-21T22:10:44</GeneratedDate>
                            	</Metadata>
                            	<Secrets Algorithm="AES">
                            		<Secret Enabled="True" ID="59A61758-4C3F-470F-9900-F7BF7A2CDAED">
                            			<EncryptedData><![CDATA[IGHYeiv2xgIx5bk3JtZvvgsex2p4KV3TL4GGDs9jfzY=]]></EncryptedData>
                            			<Key><![CDATA[Jpt2nyeCOfxDZb2UuzM92DCrBAhLiv1gXoASo2zOfL4=]]></Key>
                            			<InitializationVector><![CDATA[SOpUqOH6CRvhtF40eM8Cng==]]></InitializationVector>
                            		</Secret>
                            		<Secret Enabled="True" ID="2E4263AF-84C7-4248-A42F-E81A584BD3AD">
                            			<EncryptedData><![CDATA[gulf1oID8ueF0SgrziYCF8VDHmKNJUCg+CgolgVHE2acMvFQYL26OvaSww83lxSI]]></EncryptedData>
                            			<Key><![CDATA[3LZn9vQWAonvhSSavNectgiBex9goOFI/Nq6Wht16ao=]]></Key>
                            			<InitializationVector><![CDATA[SkQewVlEyy5Qp1O6yOWH9A==]]></InitializationVector>
                            		</Secret>
                            	</Secrets>
                            </Settings>
ExportPath                : C:\Users\Test\Downloads\EncryptedData.xml
```
