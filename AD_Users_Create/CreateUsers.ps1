#region Script-Variables

# DateStamp format
$Script:DateStampFormat = 'yyyyMMdd HH:mm:ss'

# For: New-WordBasedPassword
$Script:PasswordWordList = ( [IO.FileInfo] ( Join-Path -Path $PSScriptRoot -ChildPath 'words.txt') )

# for display purposes
$Script:HeaderCharacters = ('=' * 20)
#endregion Script-Variables

Function CreateUser
{

    <#
        .SYNOPSIS
            Creates a user in an active directory environment based on random data
        
        .DESCRIPTION
            Starting with the root container this tool randomly places users in the domain.
        
        .PARAMETER Domain
            The stored value of get-addomain is used for this.  It is used to call the PDC and other items in the domain
        
        .PARAMETER OUList
            The stored value of get-adorganizationalunit -filter *.  This is used to place users in random locations.
        
        .PARAMETER ScriptDir
            The location of the script.  Pulling this into a parameter to attempt to speed up processing.
        
        .EXAMPLE
            
     
        
        .NOTES
            
            
            Unless required by applicable law or agreed to in writing, software
            distributed under the License is distributed on an "AS IS" BASIS,
            WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
            See the License for the specific language governing permissions and
            limitations under the License.
            
            Author's blog: https://www.secframe.com
    
        
    #>
    [CmdletBinding()]
    
    param
    (
        [Parameter(Mandatory = $false,
            Position = 1,
            HelpMessage = 'Supply a result from get-addomain')]
            [Object[]]$Domain,
        [Parameter(Mandatory = $false,
            Position = 2,
            HelpMessage = 'Supply a result from get-adorganizationalunit -filter *')]
            [Object[]]$OUList,
        [Parameter(Mandatory = $false,
            Position = 3,
            HelpMessage = 'Supply the script directory for where this script is stored')]
        [string]$ScriptDir
    )
    
        if(!$PSBoundParameters.ContainsKey('Domain')){
            if($args[0]){
                $setDC = $args[0].pdcemulator
                $dnsroot = $args[0].dnsroot
            }
            else{
                $setDC = (Get-ADDomain).pdcemulator
                $dnsroot = (get-addomain).dnsroot
            }
        }
            else {
                $setDC = $Domain.pdcemulator
                $dnsroot = $Domain.dnsroot
            }
        if (!$PSBoundParameters.ContainsKey('OUList')){
            if($args[1]){
                $OUsAll = $args[1]
            }
            else{
                $OUsAll = get-adobject -Filter {objectclass -eq 'organizationalunit'} -ResultSetSize 300
            }
        }else {
            $OUsAll = $OUList
        }
        if (!$PSBoundParameters.ContainsKey('ScriptDir')){
            
            if($args[2]){

                # write-host "line 70"
                $scriptPath = $args[2]}
            else{
                    # write-host "did i get here"
                    $scriptPath = "$((Get-Location).path)\AD_Users_Create\"
            }
            
        }else{
            $scriptpath = $ScriptDir
        }
    
        function New-RandomNumber
        {
             [CmdletBinding()]
             [OutputType()]
        
             param
             (
                  [Parameter()]
                  [ValidateNotNullOrEmpty()]
                  # Minimum random number value
                  [Int]
                  $MinimumNumber = 1
                  ,
                  [Parameter()]
                  [ValidateNotNullOrEmpty()]
                  # Maximum random number value
                  [Int]
                  $MaximumNumber = 100
             )
        
             process
             {
                  # From https://stackoverflow.com/questions/6299197/rngcryptoserviceprovider-generate-number-in-a-range-faster-and-retain-distribu which references an MSDN magazine article I could not find
        
                  $rngProvider = (New-Object -TypeName System.Security.Cryptography.RNGCryptoServiceProvider)
                  while ($true)
                  {
                       if ( $MinimumNumber -eq $MaximumNumber ) { return $MaximumNumber }
        
                       $ranNumByteArr = New-Object -TypeName byte[] -ArgumentList 4
                       $rngProvider.GetBytes( $ranNumByteArr )
                       $randomNumber = [BitConverter]::ToInt32( $ranNumByteArr,0 )
        
                       $intMaxValue = (1 + [Int]::MaxValue)
                       $numRange = ( $MaximumNumber - $MinimumNumber )
                       $remainder = ( $intMaxValue - $numRange )
        
                       if ( $randomNumber -lt ( $intMaxValue - $numRange ) )
                       {
                            $retValue = ( [Int] ( $MinimumNumber + ( $randomNumber % $numRange ) ) )
        
                            if ($retValue -lt 0) { return ( $retValue * -1 ) } else { return $retValue }
                       }
                  }
             }
        }
        
    function New-WordBasedPassword
    {
         [CmdletBinding()]
         [OutputType([String])]
    
         param
         (
              [Parameter()]
              [ValidateNotNullOrEmpty()]
              # Number of words to include in password
              [Int]
              $WordCount = 1
              ,
              [Parameter()]
              [ValidateNotNullOrEmpty()]
              # Absolute path to file containing word list. Words must be a plain text file with each word or phrase on a single line
              [System.IO.FileInfo]
              $WordListLiteralPath = ( $Script:PasswordWordList )
              ,
              [Parameter()]
              # Forces reload of the world list if it is already cached
              [Switch]
              $ForceWordListReload
              ,
              [Parameter()]
              # Returns word list without spaces
              [Switch]
              $NoSpaces
         )
    
         process
         {  
              
              Write-Debug ('Word list expected location: {0}' -f $WordListLiteralPath.FullName)
    
              if (-not (Test-Path -LiteralPath $WordListLiteralPath.FullName -PathType Leaf))
              {
                   throw (New-Object -TypeName System.OperationCanceledException -ArgumentList ('Cannot access word list at "{0}". That should be there. What have you done?!  If you need to get the word file again, it is words.txt at https://github.com/dwyl/english-words' -f $WordListLiteralPath.FullName))
              }
              else
              {
                   Write-Verbose ('Word list exists at {0}' -f $WordListLiteralPath.FullName)
              }
    
              if ( $PSBoundParameters.ContainsKey('WordListLiteralPath') )
              {
                   Write-Verbose ('Custom word list provided at path: {0}' -f $WordListLiteralPath.FullName)
                   $Script:WordCache = ([String[]] @( Get-Content -LiteralPath $WordListLiteralPath.FullName -ErrorAction Stop ))
              }
              else
              {
                   if ( ($Script:WordCache.Count -ne 0) -and ($ForceWordListReload.IsPresent) )
                   {
                        Write-Verbose ('Cached word list found but a refresh of word cache is requested. Loading word list ...')
                        $wordListLoadStartTime = (Get-Date)
                        $Script:WordCache = ([String[]] @( Get-Content -LiteralPath $WordListLiteralPath.FullName -ErrorAction Stop ))
                        Write-Verbose ('Word list loaded in {0} and contains {1} words' -f ((Get-Date).Subtract($wordListLoadStartTime)),$Script:WordCache.Count)
                   }
                   elseif ($Script:WordCache.Count -gt 0)
                   {
                        Write-Verbose ('Cached word list found. Current word count: {0}' -f $Script:WordCache.Count)
                   }
                   else
                   {
                        Write-Verbose ('No cached word list found. Loading word list ...')
                        $wordListLoadStartTime = (Get-Date)
                        $Script:WordCache = ([String[]] @( Get-Content -LiteralPath $WordListLiteralPath.FullName -ErrorAction Stop ))
                        Write-Verbose ('Word list loaded in {0} and contains {1} words' -f ((Get-Date).Subtract($wordListLoadStartTime)),$Script:WordCache.Count)
                   }
              }
    
              Write-Verbose ('Generating password ...')
    
              $selectedWordList = New-Object -TypeName System.Collections.ArrayList
              for ( $i = 0; $i -lt $WordCount; $i++ )
              {
                   Write-Debug ('Password Generation Iteration {0:00}' -f $i)
    
                   $wordIndex = New-RandomNumber -MinimumNumber 0 -MaximumNumber $Script:WordCache.Count
                   Write-Debug ('Total Word Count: {0}, Word Index: {1}' -f $Script:WordCache.Count,$wordIndex)
    
                   $chosenWord = $Script:WordCache[$wordIndex]
                   $null = $selectedWordList.Add( $chosenWord )
                   Write-Debug ('Selected Word: {0}' -f $chosenWord)
              }
    
              $sBuilder = New-Object -TypeName System.Text.StringBuilder
              for ( $i = 0; $i -lt $selectedWordList.Count; $i++ )
              {
                   if ( ( ((New-RandomNumber) % 2)  -eq 0  ) )
                   {
                        $null = $sBuilder.Append( ('{0} ' -f $selectedWordList[$i].ToLower() ) )
                   }
                   else
                   {
                        if ( ( ((New-RandomNumber) % 2)  -eq 0  ) )
                        {
                             $null = $sBuilder.Append( ('{0} ' -f  $selectedWordList[$i].ToUpper() ) )
                        }
                        else
                        {
                             $null = $sBuilder.Append(  ('{0} ' -f ( (Get-Culture).TextInfo.ToTitleCase( $selectedWordList[$i].ToLower() ) ) ) )
                        }
                   }
              }
    
              $returnString = [String]::Empty
              # Remove spaces from password if requested
              if ($NoSpaces.IsPresent)
              {
                   Write-Debug ('-NoSpaces Parameter IS DETECTED. WILL remove spaces')
                   $returnString = ( [String] ( $sBuilder.ToString().Replace(' ','').Trim() ) )
              }
              else
              {
                   Write-Debug ('-NoSpaces parameter IS NOT DETECTED.WILL NOT remove spaces')
                   $returnString = ( [String] ($sBuilder.ToString().Trim() ) )
              }
    
              # Return password
              Write-Output ( $returnString )
         }
    }   
    
    function New-SWRandomPassword
    {
        <#
        .Synopsis
           Generates one or more complex passwords designed to fulfill the requirements for Active Directory
        .DESCRIPTION
           Generates one or more complex passwords designed to fulfill the requirements for Active Directory
        .EXAMPLE
           New-SWRandomPassword
           C&3SX6Kn
    
           Will generate one password with a length between 8  and 12 chars.
        .EXAMPLE
           New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
           7d&5cnaB
           !Bh776T"Fw
           9"C"RxKcY
           %mtM7#9LQ9h
    
           Will generate four passwords, each with a length of between 8 and 12 chars.
        .EXAMPLE
           New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4
           3ABa
    
           Generates a password with a length of 4 containing atleast one char from each InputString
        .EXAMPLE
           New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4 -FirstChar abcdefghijkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ
           3ABa
    
           Generates a password with a length of 4 containing atleast one char from each InputString that will start with a letter from 
           the string specified with the parameter FirstChar
        .OUTPUTS
           [String]
        .NOTES
           Written by Simon WÃ¥hlin, blog.simonw.se
           I take no responsibility for any issues caused by this script.
        .FUNCTIONALITY
           Generates random passwords
        .LINK
           http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
       
        #>
        [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
        [OutputType([String])]
        Param
        (
            # Specifies minimum password length
            [Parameter(Mandatory=$false,
                       ParameterSetName='RandomLength')]
            [ValidateScript({$_ -gt 0})]
            [Alias('Min')] 
            [int]$MinPasswordLength = 12,
            
            # Specifies maximum password length
            [Parameter(Mandatory=$false,
                       ParameterSetName='RandomLength')]
            [ValidateScript({
                    if($_ -ge $MinPasswordLength){$true}
                    else{Throw 'Max value cannot be lesser than min value.'}})]
            [Alias('Max')]
            [int]$MaxPasswordLength = 20,
    
            # Specifies a fixed password length
            [Parameter(Mandatory=$false,
                       ParameterSetName='FixedLength')]
            [ValidateRange(1,2147483647)]
            [int]$PasswordLength = 8,
            
            # Specifies an array of strings containing charactergroups from which the password will be generated.
            # At least one char from each group (string) will be used.
            [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!#%&'),
    
            # Specifies a string containing a character group from which the first character in the password will be generated.
            # Useful for systems which requires first char in password to be alphabetic.
            [String] $FirstChar,
            
            # Specifies number of passwords to generate.
            [ValidateRange(1,2147483647)]
            [int]$Count = 1
        )
        Begin {
            Function Get-Seed{
                # Generate a seed for randomization
                $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
                $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
                $Random.GetBytes($RandomBytes)
                [BitConverter]::ToUInt32($RandomBytes, 0)
            }
        }
        Process {
            For($iteration = 1;$iteration -le $Count; $iteration++){
                $Password = @{}
                # Create char arrays containing groups of possible chars
                [char[][]]$CharGroups = $InputStrings
    
                # Create char array containing all chars
                $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}
    
                # Set password length
                if($PSCmdlet.ParameterSetName -eq 'RandomLength')
                {
                    if($MinPasswordLength -eq $MaxPasswordLength) {
                        # If password length is set, use set length
                        $PasswordLength = $MinPasswordLength
                    }
                    else {
                        # Otherwise randomize password length
                        $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                    }
                }
    
                # If FirstChar is defined, randomize first char in password from that string.
                if($PSBoundParameters.ContainsKey('FirstChar')){
                    $Password.Add(0,$FirstChar[((Get-Seed) % $FirstChar.Length)])
                }
                # Randomize one char from each group
                Foreach($Group in $CharGroups) {
                    if($Password.Count -lt $PasswordLength) {
                        $Index = Get-Seed
                        While ($Password.ContainsKey($Index)){
                            $Index = Get-Seed                        
                        }
                        $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
                    }
                }
    
                # Fill out with chars from $AllChars
                for($i=$Password.Count;$i -lt $PasswordLength;$i++) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)){
                        $Index = Get-Seed                        
                    }
                    $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
                }
                Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
            }
        }
    }
    
        
    #get owner all parameters and store as variable to call upon later
           
        
    
    #=======================================================================
    
    #will work on adding things to containers later $ousall += get-adobject -Filter {objectclass -eq 'container'} -ResultSetSize 300|where-object -Property objectclass -eq 'container'|where-object -Property distinguishedname -notlike "*}*"|where-object -Property distinguishedname -notlike  "*DomainUpdates*"
    
    $ouLocation = (Get-Random $OUsAll).distinguishedname
    
    
    
    $accountType = 1..100|get-random 
    if($accountType -le 3){ # X percent chance of being a service account
    #service
    $nameSuffix = "SA"
    $description = 'Created with secframe.com/badblood.'
    #removing do while loop and making random number range longer, sorry if the account is there already
    # this is so that I can attempt to import multithreading on user creation
    
        $name = ""+ (Get-Random -Minimum 100 -Maximum 9999999999) + "$nameSuffix"
        
        
    }else{
        $surname = get-content("$($scriptpath)\Names\familynames-usa-top1000.txt")|get-random
        # Write-Host $surname
    $genderpreference = 0,1|get-random
    if ($genderpreference -eq 0){$givenname = get-content("$($scriptpath)\Names\femalenames-usa-top1000.txt")|get-random}else{$givenname = get-content($scriptpath + '\Names\malenames-usa-top1000.txt')|get-random}
    $name = $givenname+"_"+$surname
    }
    
        $departmentnumber = [convert]::ToInt32('9999999') 
        
        
    #Need to figure out how to do the L attribute
    $description = 'Created with secframe.com/badblood.'

    $pwd = ""
    $passwordType = 1..1000|get-random
    if ($passwordType -lt 50) { 
        $pwd = New-SWRandomPassword -MinPasswordLength 12 -MaxPasswordLength 24
    }
    elseif ($passwordType -ge 50 -And $passwordType -lt 100) {
        $pwd = "Winter22"
    }
    elseif ($passwordType -ge 100 -And $passwordType -lt 200) {
        $pwd = "fakedomainsvc1"
    }
    elseif ($passwordType -ge 200 -And $passwordType -lt 800) {
        while($pwd.length -lt 7) {
            $pwd_first = New-WordBasedPassword -WordCount 1 -NoSpaces
            $pwd_second = New-SWRandomPassword -MinPasswordLength 1 -MaxPasswordLength 4 -InputStrings 12345
            $pwd = "$($pwd_first)$($pwd_second)"
        }
    }
    else {
        while($pwd.length -lt 7) {
            $pwd_first = New-WordBasedPassword -WordCount 3 -NoSpaces
            $pwd_second = New-SWRandomPassword -MinPasswordLength 1 -MaxPasswordLength 4 -InputStrings 12345
            $pwd = "$($pwd_first)$($pwd_second)"
        }
    }
    #$pwd = New-SWRandomPassword -MinPasswordLength 6 -MaxPasswordLength 16
    #======================================================================
    # 
    
    $passwordinDesc = 1..1000|get-random
    #$pwd = New-SWRandomPassword -MinPasswordLength 6 -MaxPasswordLength 16
    if ($passwordinDesc -lt 10) { 
        $description = 'Just so I dont forget my password is ' + $pwd 
    }else{}
    if($name.length -gt 20){
        $name = $name.substring(0,20)
    }

    $exists = $null
    try {
        $exists = Get-ADUSer $name -ErrorAction Stop
    } catch{}

    if($exists){
        return $true
    }

    new-aduser -server $setdc  -Description $Description -DisplayName $name -name $name -SamAccountName $name -Surname $name -Enabled $true -Path $ouLocation -AccountPassword (ConvertTo-SecureString ($pwd) -AsPlainText -force)
    
    
    
        
    
    $pwd = ''

    #==============================
    # Set Does Not Require Pre-Auth for ASREP
    #==============================
    
    $setASREP = 1..1000|get-random
    if($setASREP -lt 20){
	Get-ADuser $name | Set-ADAccountControl -DoesNotRequirePreAuth:$true
    }
    
    #===============================
    #SET ATTRIBUTES - no additional attributes set at this time besides UPN
    #Todo: Set SPN for kerberoasting.  Example attribute edit is in createcomputers.ps1
    #===============================
    
    $upn = $name + '@' + $dnsroot
    try{Set-ADUser -Identity $name -UserPrincipalName "$upn" }
    catch{}
    
    # return $false
    ################################
    #End Create User Objects
    ################################
    
    }
    
