## Microsoft Function Naming Convention: http://msdn.microsoft.com/en-us/library/ms714428(v=vs.85).aspx

#region Function Invoke-SymmectricCryptography
Function Invoke-SymmectricCryptography
    {
        <#
          .SYNOPSIS
          Performs value encryption or decryption using a specified algorithm.
          
          .DESCRIPTION
          A random key and initialization vector (IV) will be generated with each execution for maximum security.
          
          This means that the resulting encrypted data will NEVER be the same, even if the value to be encrypted is!
          
          This function is great for encrypting data that will NOT be transmitted over a network. In other words, data at rest.

   	  If transmitting the data over a network is required, consider breaking the encrypted data, key, and initialization vector apart.
          
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
        #>
        
        [CmdletBinding(ConfirmImpact = 'Low', DefaultParameterSetName = 'Encryption', PositionalBinding = $True)]
       
        Param
          (        
              [Parameter(Mandatory=$True, ParameterSetName = 'Encryption')]
              [Switch]$Encrypt,

              [Parameter(Mandatory=$True, ParameterSetName = 'Decryption')]
              [Switch]$Decrypt,

              [Parameter(Mandatory=$True, ParameterSetName = 'Encryption')]
              [Parameter(Mandatory=$True, ParameterSetName = 'Decryption')]
              [ValidateNotNullOrEmpty()]
              [ValidateSet('AES', 'DES', 'RC2', 'TripleDES')]
              [String]$Algorithm,

              [Parameter(Mandatory=$True, ParameterSetName = 'Encryption')]
              [ValidateNotNullOrEmpty()]
              [String[]]$Data,

              [Parameter(Mandatory=$True, ParameterSetName = 'Decryption')]
              [ValidateNotNullOrEmpty()]
              [String]$EncryptedData,

              [Parameter(Mandatory=$True, ParameterSetName = 'Decryption')]
              [ValidateNotNullOrEmpty()]
              [ValidatePattern('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$')]
              [String]$Key,

              [Parameter(Mandatory=$True, ParameterSetName = 'Decryption')]
              [ValidateNotNullOrEmpty()]
              [ValidatePattern('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$')]
              [String]$InitializationVector,
                
              [Parameter(Mandatory=$False, ParameterSetName = 'Encryption')]
              [Switch]$Export,

              [Parameter(Mandatory=$False, ParameterSetName = 'Encryption')]
              [ValidateNotNullOrEmpty()]
              [ValidateSet('JSON', 'XML')]
              [String]$ExportFormat,

              [Parameter(Mandatory=$False, ParameterSetName = 'Encryption')]
              [ValidateNotNullOrEmpty()]
              [ValidateScript({$_ -imatch '(^([A-Z]\:|\\\\.*\\.*)\\.*\.(json|xml)$)'})]
              [System.IO.FileInfo]$ExportPath,
                                            
              [Parameter(Mandatory=$False)]
              [Switch]$ContinueOnError      
          )
                    
        Begin
          {

              
              Try
                {
                    $DateTimeLogFormat = 'dddd, MMMM dd, yyyy @ hh:mm:ss.FFF tt'  ###Monday, January 01, 2019 @ 10:15:34.000 AM###
                    [ScriptBlock]$GetCurrentDateTimeLogFormat = {(Get-Date).ToString($DateTimeLogFormat)}
                    $DateTimeMessageFormat = 'MM/dd/yyyy HH:mm:ss.FFF'  ###03/23/2022 11:12:48.347###
                    [ScriptBlock]$GetCurrentDateTimeMessageFormat = {(Get-Date).ToString($DateTimeMessageFormat)}
                    $DateFileFormat = 'yyyyMMdd'  ###20190403###
                    [ScriptBlock]$GetCurrentDateFileFormat = {(Get-Date).ToString($DateFileFormat)}
                    $DateTimeFileFormat = 'yyyyMMdd_HHmmss'  ###20190403_115354###
                    [ScriptBlock]$GetCurrentDateTimeFileFormat = {(Get-Date).ToString($DateTimeFileFormat)}
                    $DateTimeXMLFormat = 'yyyy-MM-ddTHH:mm:ss'  ###2022-10-24T12:45:15###
                    [ScriptBlock]$GetCurrentDateTimeXMLFormat = {(Get-Date).ToString($DateTimeXMLFormat)}
                    $TextInfo = (Get-Culture).TextInfo
                    $LoggingDetails = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'    
                      $LoggingDetails.Add('LogMessage', $Null)
                      $LoggingDetails.Add('WarningMessage', $Null)
                      $LoggingDetails.Add('ErrorMessage', $Null)
                    $CommonParameterList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                      $CommonParameterList.AddRange([System.Management.Automation.PSCmdlet]::CommonParameters)
                      $CommonParameterList.AddRange([System.Management.Automation.PSCmdlet]::OptionalCommonParameters)

                    [ScriptBlock]$ErrorHandlingDefinition = {
                                                                $ErrorMessageList = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                  $ErrorMessageList.Add('Message', $_.Exception.Message)
                                                                  $ErrorMessageList.Add('Category', $_.Exception.ErrorRecord.FullyQualifiedErrorID)
                                                                  $ErrorMessageList.Add('Script', $_.InvocationInfo.ScriptName)
                                                                  $ErrorMessageList.Add('LineNumber', $_.InvocationInfo.ScriptLineNumber)
                                                                  $ErrorMessageList.Add('LinePosition', $_.InvocationInfo.OffsetInLine)
                                                                  $ErrorMessageList.Add('Code', $_.InvocationInfo.Line.Trim())

                                                                ForEach ($ErrorMessage In $ErrorMessageList.GetEnumerator())
                                                                  {
                                                                      $LoggingDetails.ErrorMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) -  ERROR: $($ErrorMessage.Key): $($ErrorMessage.Value)"
                                                                      Write-Warning -Message ($LoggingDetails.ErrorMessage)
                                                                  }

                                                                Switch (($ContinueOnError.IsPresent -eq $False) -or ($ContinueOnError -eq $False))
                                                                  {
                                                                      {($_ -eq $True)}
                                                                        {                  
                                                                            Throw
                                                                        }
                                                                  }
                                                            }
                    
                    #Determine the date and time we executed the function
                      $FunctionStartTime = (Get-Date)
                    
                    [String]$FunctionName = $MyInvocation.MyCommand
                    [System.IO.FileInfo]$InvokingScriptPath = $MyInvocation.PSCommandPath
                    [System.IO.DirectoryInfo]$InvokingScriptDirectory = $InvokingScriptPath.Directory.FullName
                    [System.IO.FileInfo]$FunctionPath = "$($InvokingScriptDirectory.FullName)\Functions\$($FunctionName).ps1"
                    [System.IO.DirectoryInfo]$FunctionDirectory = "$($FunctionPath.Directory.FullName)"
                    
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function `'$($FunctionName)`' is beginning. Please Wait..."
                    Write-Verbose -Message ($LoggingDetails.LogMessage)
              
                    #Define Default Action Preferences
                      $ErrorActionPreference = 'Stop'
                      
                    [String[]]$AvailableScriptParameters = (Get-Command -Name ($FunctionName)).Parameters.GetEnumerator() | Where-Object {($_.Value.Name -inotin $CommonParameterList)} | ForEach-Object {"-$($_.Value.Name):$($_.Value.ParameterType.Name)"}
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Available Function Parameter(s) = $($AvailableScriptParameters -Join ', ')"
                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                    [String[]]$SuppliedScriptParameters = $PSBoundParameters.GetEnumerator() | ForEach-Object {"-$($_.Key):$($_.Value.GetType().Name)"}
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Supplied Function Parameter(s) = $($SuppliedScriptParameters -Join ', ')"
                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Execution of $($FunctionName) began on $($FunctionStartTime.ToString($DateTimeLogFormat))"
                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Parameter Set Name: $($PSCmdlet.ParameterSetName)"
                    Write-Verbose -Message ($LoggingDetails.LogMessage)
                                        
                    #Create an object that will contain the functions output.
                      $OutputObjectProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                      
                    #Determine the fully qualified Crypto Service Provider based on the specified algorithm
                      Switch ($Algorithm)
                        {
                            {($_ -iin @('AES'))}
                              {
                                  $CryptoServiceProvider = 'System.Security.Cryptography.AESCryptoServiceProvider'
                                  $CryptoServiceProviderName = 'AESCryptoServiceProvider'
                              }

                            {($_ -iin @('DES'))}
                              {
                                  $CryptoServiceProvider = 'System.Security.Cryptography.DESCryptoServiceProvider'
                                  $CryptoServiceProviderName = 'DESCryptoServiceProvider'
                              }

                            {($_ -iin @('RC2'))}
                              {
                                  $CryptoServiceProvider = 'System.Security.Cryptography.RC2CryptoServiceProvider'
                                  $CryptoServiceProviderName = 'RC2CryptoServiceProvider'
                              }

                            {($_ -iin @('TripleDES'))}
                              {
                                  $CryptoServiceProvider = 'System.Security.Cryptography.TripleDESCryptoServiceProvider'
                                  $CryptoServiceProviderName = 'TripleDESCryptoServiceProvider'
                              }
                        }

                    #Create an object that will contain that encrypted data objects
                      $EncryptedDataOutputObjectList = New-Object -TypeName 'System.Collections.Generic.List[System.Management.Automation.PSObject]'
                }
              Catch
                {
                    $ErrorHandlingDefinition.Invoke()
                }
              Finally
                {
                    
                }
          }

        Process
          {           
              Try
                {  
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to symmetrically $($PSCmdlet.ParameterSetName.Replace('ion', '').ToLower()) the provided data using the `"$($Algorithm)`" cryptographic service provider. Please Wait..." 
                    Write-Verbose -Message ($LoggingDetails.LogMessage)
                
                    Switch ($PSCmdlet.ParameterSetName)
                      {
                          {($_ -iin @('Encryption'))}
                            {   
                                $OutputObjectProperties.Algorithm = $Algorithm
                                $OutputObjectProperties.CryptoServiceProvider = $CryptoServiceProvider
                                $OutputObjectProperties.CryptoServiceProviderName = $CryptoServiceProviderName
                                
                                $DataObjectCount = ($Data | Measure-Object).Count
                                
                                For ($DataObjectIndex = 0; $DataObjectIndex -lt $DataObjectCount; $DataObjectIndex++)
                                  {
                                      $DataObject = $Data[$DataObjectIndex]

                                      $EncryptedDataOutputObjectProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                        $EncryptedDataOutputObjectProperties.Algorithm = $Algorithm

                                      $CryptoServiceDictionary = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                        $CryptoServiceDictionary.Encoder = [System.Text.Encoding]::UTF8
                                        $CryptoServiceDictionary.Provider = New-Object -TypeName ($CryptoServiceProvider)
                                          $CryptoServiceDictionary.Provider.Mode = [System.Security.Cryptography.CipherMode]::CBC
                                          $CryptoServiceDictionary.Provider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                                          $CryptoServiceDictionary.Provider.GenerateKey()        
                                          $CryptoServiceDictionary.Provider.GenerateIV()

                                      $CryptoServiceDictionary.Encryptor = $CryptoServiceDictionary.Provider.CreateEncryptor($CryptoServiceDictionary.Provider.Key, $CryptoServiceDictionary.Provider.IV)

                                      $CryptoServiceDictionary.DataBytes = $CryptoServiceDictionary.Encoder.GetBytes($DataObject)
                                
                                      $CryptoServiceDictionary.MemoryStream = New-Object -TypeName 'System.IO.MemoryStream'
                                
                                      $CryptoServiceDictionary.CryptoStreamMode = [System.Security.Cryptography.CryptoStreamMode]::Write
                                
                                      $CryptoServiceDictionary.CryptoStreamArgumentList = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                                        $CryptoServiceDictionary.CryptoStreamArgumentList.Add($CryptoServiceDictionary.MemoryStream)
                                        $CryptoServiceDictionary.CryptoStreamArgumentList.Add($CryptoServiceDictionary.Encryptor)
                                        $CryptoServiceDictionary.CryptoStreamArgumentList.Add($CryptoServiceDictionary.CryptoStreamMode)
                                
                                      $CryptoServiceDictionary.CryptoStream = New-Object -TypeName 'System.Security.Cryptography.CryptoStream' -ArgumentList ($CryptoServiceDictionary.CryptoStreamArgumentList.ToArray())

                                      $CryptoServiceDictionary.StreamWriterArgumentList = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                                        $CryptoServiceDictionary.StreamWriterArgumentList.Add($CryptoServiceDictionary.CryptoStream)

                                      $CryptoServiceDictionary.StreamWriter = New-Object -TypeName 'System.IO.StreamWriter' -ArgumentList ($CryptoServiceDictionary.StreamWriterArgumentList.ToArray())
                                        $CryptoServiceDictionary.StreamWriter.Write($CryptoServiceDictionary.DataBytes, 0, $CryptoServiceDictionary.DataBytes.Length)

                                      $Null = $CryptoServiceDictionary.StreamWriter.Close()
                                      $Null = $CryptoServiceDictionary.CryptoStream.Close()
                                      $Null = $CryptoServiceDictionary.MemoryStream.Close()

                                      $EncryptedDataOutputObjectProperties.EncryptedData = [Convert]::ToBase64String($CryptoServiceDictionary.MemoryStream.ToArray())
                                      $EncryptedDataOutputObjectProperties.Key = [Convert]::ToBase64String($CryptoServiceDictionary.Provider.Key)
                                      $EncryptedDataOutputObjectProperties.InitializationVector = [Convert]::ToBase64String($CryptoServiceDictionary.Provider.IV)
                                      $EncryptedDataOutputObjectProperties.DKIV = "$($EncryptedDataOutputObjectProperties.EncryptedData):$($EncryptedDataOutputObjectProperties.Key):$($EncryptedDataOutputObjectProperties.InitializationVector)"

                                      $EncryptedDataOutputObject = New-Object -TypeName 'System.Management.Automation.PSObject' -Property ($EncryptedDataOutputObjectProperties)
                                      
                                      $EncryptedDataOutputObjectList.Add($EncryptedDataOutputObject)

                                      $Null = $CryptoServiceDictionary.Clear()
                                  }  
                            }

                          {($_ -iin @('Decryption'))}
                            {
                                $CryptoServiceDictionary = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                  $CryptoServiceDictionary.Encoder = [System.Text.Encoding]::UTF8
                                  $CryptoServiceDictionary.Provider = New-Object -TypeName ($CryptoServiceProvider)
                                    $CryptoServiceDictionary.Provider.Mode = [System.Security.Cryptography.CipherMode]::CBC
                                    $CryptoServiceDictionary.Provider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                                    $CryptoServiceDictionary.Provider.Key = [System.Convert]::FromBase64String($Key)
                                    $CryptoServiceDictionary.Provider.IV = [System.Convert]::FromBase64String($InitializationVector)
                                
                                $CryptoServiceDictionary.Decryptor = $CryptoServiceDictionary.Provider.CreateDecryptor($CryptoServiceDictionary.Provider.Key, $CryptoServiceDictionary.Provider.IV)
                                
                                $CryptoServiceDictionary.DataBytes = [System.Convert]::FromBase64String($EncryptedData)
                                
                                $CryptoServiceDictionary.MemoryStreamArgumentList = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                                  $CryptoServiceDictionary.MemoryStreamArgumentList.Add($CryptoServiceDictionary.DataBytes)
                                  $CryptoServiceDictionary.MemoryStreamArgumentList.Add(0)
                                  $CryptoServiceDictionary.MemoryStreamArgumentList.Add($CryptoServiceDictionary.DataBytes.Length)

                                $CryptoServiceDictionary.MemoryStream = New-Object -TypeName 'System.IO.MemoryStream' -ArgumentList ($CryptoServiceDictionary.MemoryStreamArgumentList.ToArray())
                                
                                $CryptoServiceDictionary.CryptoStreamMode = [System.Security.Cryptography.CryptoStreamMode]::Read
                                
                                $CryptoServiceDictionary.CryptoStreamArgumentList = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                                  $CryptoServiceDictionary.CryptoStreamArgumentList.Add($CryptoServiceDictionary.MemoryStream)
                                  $CryptoServiceDictionary.CryptoStreamArgumentList.Add($CryptoServiceDictionary.Decryptor)
                                  $CryptoServiceDictionary.CryptoStreamArgumentList.Add($CryptoServiceDictionary.CryptoStreamMode)
                                
                                $CryptoServiceDictionary.CryptoStream = New-Object -TypeName 'System.Security.Cryptography.CryptoStream' -ArgumentList ($CryptoServiceDictionary.CryptoStreamArgumentList.ToArray())
                                                                
                                $CryptoServiceDictionary.StreamReaderArgumentList = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                                  $CryptoServiceDictionary.StreamReaderArgumentList.Add($CryptoServiceDictionary.CryptoStream)
                                
                                $CryptoServiceDictionary.StreamReader = New-Object -TypeName 'System.IO.StreamReader' -ArgumentList ($CryptoServiceDictionary.StreamReaderArgumentList.ToArray())
                                                                                                  
                                [String]$DecryptedData = $CryptoServiceDictionary.StreamReader.ReadToEnd()
                                
                                $OutputObjectProperties.DecryptedData = $DecryptedData

                                $Null = $CryptoServiceDictionary.MemoryStream.Close()
                                $Null = $CryptoServiceDictionary.CryptoStream.Close()
                                $Null = $CryptoServiceDictionary.MemoryStream.Close()

                                $Null = $CryptoServiceDictionary.Clear()
                            }
                      }
                }
              Catch
                {
                    $ErrorHandlingDefinition.Invoke()
                }
              Finally
                {
                    
                }
          }
        
        End
          {                                        
              Try
                {
                    #Determine the date and time the function completed execution
                      $FunctionEndTime = (Get-Date)

                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Execution of $($FunctionName) ended on $($FunctionEndTime.ToString($DateTimeLogFormat))"
                      Write-Verbose -Message ($LoggingDetails.LogMessage)

                    #Log the total script execution time  
                      $FunctionExecutionTimespan = New-TimeSpan -Start ($FunctionStartTime) -End ($FunctionEndTime)

                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function execution took $($FunctionExecutionTimespan.Hours.ToString()) hour(s), $($FunctionExecutionTimespan.Minutes.ToString()) minute(s), $($FunctionExecutionTimespan.Seconds.ToString()) second(s), and $($FunctionExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
                      Write-Verbose -Message ($LoggingDetails.LogMessage)
                    
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function `'$($FunctionName)`' is completed."
                    Write-Verbose -Message ($LoggingDetails.LogMessage)
                }
              Catch
                {
                    $ErrorHandlingDefinition.Invoke()
                }
              Finally
                {  
                    Switch ($PSCmdlet.ParameterSetName)
                      {
                          {($_ -iin @('Encryption'))}
                            {
                                $OutputObjectProperties.EncryptedDataObjectList = $EncryptedDataOutputObjectList
                                
                                Switch ($Export.IsPresent)
                                  {
                                      {($_ -eq $True)}
                                        {
                                            Switch ($True)
                                              {
                                                  {([String]::IsNullOrEmpty($ExportFormat) -eq $True) -or ([String]::IsNullOrWhiteSpace($ExportFormat) -eq $True)}
                                                    {
                                                        [String]$ExportFormat = 'JSON'
                                                    }
                                              }

                                            $OutputObjectProperties.ExportFormat = $ExportFormat
                                            
                                            Switch ($ExportFormat)
                                              {
                                                  {($_ -iin @('JSON'))}
                                                    {
                                                        $OutputObjectProperties.ExportContent = $OutputObjectProperties | ConvertTo-JSON -Depth 10 -Compress:$False
                                                    }

                                                  {($_ -iin @('XML'))}
                                                    {
                                                        $XMLWriterSettings = New-Object -TypeName 'System.XML.XMLWriterSettings'
                                                          $XMLWriterSettings.Indent = $True
                                                          $XMLWriterSettings.IndentChars = "`t" * 1
                                                          $XMLWriterSettings.Encoding = [System.Text.Encoding]::Default
                                                          $XMLWriterSettings.NewLineHandling = [System.XML.NewLineHandling]::None
                                                          $XMLWriterSettings.ConformanceLevel = [System.XML.ConformanceLevel]::Document
                                                          $XMLWriterSettings.OmitXmlDeclaration = $False

                                                        $XMLStringBuilder = New-Object -TypeName 'System.Text.StringBuilder'                                                        

                                                        $XMLWriter = [System.XML.XMLTextWriter]::Create($XMLStringBuilder, $XMLwritersettings)

                                                        [ScriptBlock]$AddXMLWriterNewLine = {$XMLWriter.WriteWhitespace(("`r`n" * 2))}
  
                                                        $Null = $XMLWriter.WriteStartDocument()

                                                        $Null = $AddXMLWriterNewLine.Invoke()

                                                        $Null = $XMLWriter.WriteStartElement('Settings')

                                                        $Null = $XMLWriter.WriteStartElement('Metadata')
                                                          
                                                        $XMLWriter.WriteElementString('GeneratedDate', $GetCurrentDateTimeXMLFormat.InvokeReturnAsIs())
                                                       
                                                        $Null = $XMLWriter.WriteEndElement()

                                                        $Null = $XMLWriter.WriteStartElement('Secrets')

                                                        ForEach ($OutputObjectProperty In $OutputObjectProperties.GetEnumerator())
                                                          {
                                                              Switch ($OutputObjectProperty.Key)
                                                                {
                                                                    {($_ -iin @('Algorithm'))}
                                                                      {
                                                                          $XMLWriter.WriteAttributeString($OutputObjectProperty.Key, $OutputObjectProperty.Value)
                                                                      }
                                                                }
                                                          }

                                                        ForEach ($EncryptedDataObject In $OutputObjectProperties.EncryptedDataObjectList)
                                                          {
                                                              $SecretID = [System.GUID]::NewGUID().ToString().ToUpper()
                                                              
                                                              $Null = $XMLWriter.WriteStartElement('Secret')

                                                              $Null = $XMLWriter.WriteAttributeString('Enabled', $True)
                                                              $Null = $XMLWriter.WriteAttributeString('ID', $SecretID)
                                                              
                                                              ForEach ($EncryptedDataObjectProperty In $EncryptedDataObject.PSObject.Properties)
                                                                {    
                                                                    Switch (($Null -ine $EncryptedDataObjectProperty.Value) -and ([String]::IsNullOrEmpty($EncryptedDataObjectProperty.Value) -eq $False) -and ([String]::IsNullOrWhiteSpace($EncryptedDataObjectProperty.Value) -eq $False))
                                                                      {
                                                                          {($_ -eq $True)}
                                                                            {
                                                                                Switch ($True)
                                                                                  {
                                                                                      {($EncryptedDataObjectProperty.Name -iin @('EncryptedData', 'Key', 'InitializationVector'))}
                                                                                        {
                                                                                            $Null = $XMLWriter.WriteStartElement($EncryptedDataObjectProperty.Name)
                                                                                            
                                                                                            $XMLWriter.WriteCData($EncryptedDataObjectProperty.Value)

                                                                                            $Null = $XMLWriter.WriteEndElement()
                                                                                        }
                                                                                  }  
                                                                            }
                                                                      }
                                                                }

                                                              $Null = $XMLWriter.WriteEndElement()
                                                          }
                                                         
                                                        $Null = $XMLWriter.WriteEndElement()
                                                        $Null = $XMLWriter.WriteEndElement()
                                                        $Null = $XMLWriter.WriteEndDocument()
                                                        $Null = $XMLWriter.Flush()
                                                        $Null = $XMLWriter.Close()

                                                        $OutputObjectProperties.ExportContent = $XMLStringBuilder.ToString() -ireplace '(utf\-\d+)', 'utf-8'
                                                    }
                                              }

                                            Switch (([String]::IsNullOrEmpty($ExportPath) -eq $False) -and ([String]::IsNullOrEmpty($ExportPath) -eq $False))
                                              {
                                                  {($_ -eq $True)}
                                                    {
                                                        $OutputObjectProperties.ExportPath = $ExportPath.FullName
                                                        
                                                        Switch ([System.IO.Directory]::Exists($ExportPath.Directory.FullName))
                                                          {
                                                              {($_ -eq $False)}
                                                                {
                                                                    $Null = [System.IO.Directory]::CreateDirectory($ExportPath.Directory.FullName)
                                                                }
                                                          }

                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to export the encrypted contents for $($DataObjectCount) secret(s) in $($ExportFormat) format. Please Wait. [Path: $($ExportPath.FullName)]"
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                        $Null = [System.IO.File]::WriteAllText($ExportPath.FullName, $OutputObjectProperties.ExportContent, $XMLWriterSettings.Encoding)
                                                    }

                                                  Default
                                                    {
                                                        $OutputObjectProperties.ExportPath = $Null
                                                    }
                                              }
                                        }
                                  }
                            }
                      }

                    Switch ($PSCmdlet.ParameterSetName)
                      {
                          {($_ -iin @('Encryption'))}
                            {
                                $OutputObject = New-Object -TypeName 'System.Management.Automation.PSObject' -Property ($OutputObjectProperties)
                    
                                Write-Output -InputObject ($OutputObject)
                            }

                          {($_ -iin @('Decryption'))}
                            {
                                #$OutputObject = $DecryptedData
                                
                                $OutputObject = New-Object -TypeName 'System.Management.Automation.PSObject' -Property ($OutputObjectProperties)
                    
                                Write-Output -InputObject ($OutputObject)
                            }
                      }
                }
          }
    }
#endregion
