# Invoke-SymmectricCryptography
Performs value encryption or decryption using a specified algorithm.

          .SYNOPSIS
          Performs value encryption or decryption using a specified algorithm.
          
          .DESCRIPTION
          A random key and initialization vector (IV) will be generated with each execution for maximum security.
          
          This means that the resulting encrypted data will NEVER be the same, even if the value to be encrypted is!
          
          This function is great for encrypting data that will NOT be transmitted over a network. In other words, data at rest.
          
          .PARAMETER Encrypt
	        Specifies that encryption will be performed.

          .PARAMETER Decrypt
	        Specifies that decryption will be performed.

          .PARAMETER Algorithm
	        Specifies the algorithm used for encryption or decryption.

          .PARAMETER Data
	        Specifies the original string value that will be encrypted.

          .PARAMETER EncryptedData
	        Specifies the previously encrypted string value that will be decrypted.

          .PARAMETER Key
	        Specifies the decryption key that is required for decryption.

          .PARAMETER InitializationVector
	        Specifies the initialization vector (IV) that is required for decryption.

          .PARAMETER Export
	        Specifies that the encrypted data is to be exported.

          .PARAMETER ExportFormat
	        Specifies the format that the encrypted data will be exported in.

          .PARAMETER ExportPath
	        Specifies the path that the encrypted data will be exported to.

          .PARAMETER ContinueOnError
	        Specifies that errors will be logged as warnings, but not considered fatal.
          
          .EXAMPLE
          $EncryptionResult = Invoke-SymmectricCryptography -Encrypt -Algorithm AES -Data 'SomeValueRequiringEncryption'

          Write-Output -InputObject ($EncryptionResult)

          .EXAMPLE
          $DecryptionResult = Invoke-SymmectricCryptography -Decrypt -Algorithm AES -Data 'msDFP5hUQo8flkb+qnRSl+1yEaKEhl5Lr3LBfClXSMY=' -Key 'oc5cuCuOhw1qJvwr1iwHr9mOWXmLTMCgw1zlIOZDf78=' -InitializationVector 'zDpcPE2a4YWF/gFmGQoZhQ=='

          Write-Output -InputObject ($DecryptionResult)

          .EXAMPLE
          $InvokeSymmectricCryptographyParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
	          $InvokeSymmectricCryptographyParameters.Encrypt = $True
	          $InvokeSymmectricCryptographyParameters.Algorithm = 'AES'
	          $InvokeSymmectricCryptographyParameters.Data = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
              $InvokeSymmectricCryptographyParameters.Data.Add("AValueThatNeedsToBeEncrypted")
              $InvokeSymmectricCryptographyParameters.Data.Add("AnotherValueThatNeedsToBeEncrypted")
	          $InvokeSymmectricCryptographyParameters.Export = $True
	          $InvokeSymmectricCryptographyParameters.ExportFormat = 'XML'
	          $InvokeSymmectricCryptographyParameters.ExportPath = "$($Env:UserProfile)\Downloads\EncryptedData.xml"
	          $InvokeSymmectricCryptographyParameters.ContinueOnError = $False
	          $InvokeSymmectricCryptographyParameters.Verbose = $True

          $EncryptionResult = Invoke-SymmectricCryptography @InvokeSymmectricCryptographyParameters

          Write-Output -InputObject ($EncryptionResult)

          .EXAMPLE
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

          .EXAMPLE
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

          .NOTES
          Any useful tidbits

          .LINK
          https://codeandkeep.com/PowerShell-Aes-Encryption/
	   
          .LINK
          https://smsagent.blog/2022/09/23/encrypting-sensitive-data-for-transit-or-rest-with-powershell/
	  
          .LINK
          https://stackoverflow.com/questions/67883498/powershell-password-encryption-decryption-with-key
	  
          .LINK
          https://medium.com/@sumindaniro/encrypt-decrypt-data-with-powershell-4a1316a0834b
	  
