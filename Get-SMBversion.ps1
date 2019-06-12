<#
 .SYNOPSIS
    Author: Christophe Poirier
    Version: 1.00 (17/08/2018) - first version
    Version: 1.10 (22/08/2018) - manage timeout and added status ('timeou't or 'not reachable') to SMBVersion column
                                 suppress start-sleep in Getoutput function to speed up large scan

    Version: 2.00 (13/11/2018) - Add Domain name to csv (not used to query), SMBV1 switch to query SMV1 Dialect only
                                 Improve error handling, new output.

 .DESCRIPTION
    Get higher SMB dialect from a given computer name.

    No authentication required
    TCP port 445 must be reachable
    Not additional powershell module required
    Tested on windows 7, 10 and windows 2012 R2
    Use same dialect list as Windows 10.
    
    Function used:
        PushToTcpPort
        GetOutput

 .PARAMETER   
    -ComputerName   : Computer name or IP
    -TrustedDomain  : FQDN Domain Name (not used to query only to output reference 
    -SMBV1          : Query SMBV1 only
    -Verbose        : To display response packet to negotiate query

 .EXAMPLE 


    # SMBV2 and SMBV1 =================

    .\Get-SMBversion.ps1  (default current computer)

    .\Get-SMBversion.ps1 -ComputerName W2012R2SRV -TrustedDomain contoso.com

    Negotiating SMBV2 dialect on:  W2012R2SRV
     SMBV2 Negotiated Dialect   :  SMB 3.2
    Negotiating SMBV1 dialect on:  W2012R2SRV
     SMBV1 Negotiated Dialect   :  NT LM 0.12

    Domain            : contoso.com
    Host              : W2012R2SRV
    IsSmbV1           : True
    DialectSmbV1      : NT LM 0.12
    IsSmbV2           : True
    DialectSmbv2      : 3.2
    Signing           : 0001
    ServerStartupTime : 11/5/2018 2:21:40 PM


    # SMBV2 and SMBV1 to host supporting only SMBV2 

    .\Get-SMBversion.ps1 -ComputerName smbv2onlyhost  -TrustedDomain contoso.com

    Negotiating SMBV2 dialect on:  smbv2onlyhost
     SMBV2 Negotiated Dialect   :  SMB 3.11
    Negotiating SMBV1 dialect on:  smbv2onlyhost
     Not any requested dialects found on this host. Timeout: True

    Domain            : contos0.com
    Host              : smbv2onlyhost
    IsSmbV1           : False
    DialectSmbV1      : na
    IsSmbV2           : True
    DialectSmbv2      : 3.11
    Signing           : 0001
    ServerStartupTime : 10/8/2018 2:53:16 PM


    # SMBV1 only ======================

    .\Get-SMBversion.ps1 -ComputerName W2012R2SRV -TrustedDomain contoso.com -smbv1 

    Negotiating SMB dialect on:  W2012R2SRVT
    Negotiated Dialect        :  NT LM 0.12

    Domain       : contoso.com
    Host         : W2012R2SRV
    IsSmbV1      : True
    DialectSmbV1 : NT LM 0.12


    # Do not support pipeline option but you can use a server array

    get-content .\myserverlist.txt
    $server | foreach {.\Get-SMBversion.ps1 -computername $_}
    
    Reference:
        https://msdn.microsoft.com/en-us/library/cc246482.aspx
        https://msdn.microsoft.com/en-us/library/cc246561.aspx
#>


[CmdletBinding()]
Param(
   #[Parameter(Mandatory=$True)]
   [Parameter()]
   [string]$ComputerName = $env:COMPUTERNAME,
   [string]$TrustedDomain,
   [switch]$SMBV1 = $false
)

function PushToTcpPort
{
    param ([Byte[]] $bytearray, [Byte[]] $bytearray2, [Byte[]] $bytearray3, [String] $ipaddress, [Int32] $port)

    $TcpTimeout = 3000
    # TCP connect with timeout
    try
    {
        $tcpclient = New-Object -TypeName system.Net.Sockets.TcpClient
        $iar = $tcpclient.BeginConnect($ipaddress,$port,$null,$null)

        $wait = $iar.AsyncWaitHandle.WaitOne($TcpTimeout,$false)
        if(!$wait)
        {
            write-host "Negotiated Dialect        :  TcpClient timeout to connect to $ipaddress`:$port" -ForegroundColor yellow 

            $tcpclient.Close()
            return
        }
        else
        {
            # Close the connection and report the error if there is one
            $script:TCPConnected = $tcpclient.Connected
        }
    }
    catch 
    {
            write-host "Negotiated Dialect        :  TcpClient Failed to connect to $ipaddress`:$port" -ForegroundColor red 
            write-host '  PushToTcpPort: TcpClient connection:' $script:TCPConnected -ForegroundColor Magenta
            $tcpclient.Close()
            return
            exit
    }


    # Send bytes
    $networkstream = $tcpclient.getstream()
    #write(payload,starting offset,number of bytes to send)
    $networkstream.write($bytearray,0,$bytearray.length)

    GetOutput

    if(-not $script:IsSMB1 -and -not $script:timeOut){
       # Dialect 2.002 does not need an second query as it does not respond with a wilcard or timeout
       if($script:SMBVersion2 -ne '2.002'){
         # get SMV v2 dialects after receive SMB 2.??? wilcard dialect during first query
         $networkstream.write($bytearray2,0,$bytearray2.length)
         GetOutput
       }
    }


    $networkstream.close(1) #Wait 1 second before closing TCP session.
    $tcpclient.Close()
}

## Read output from a remote host
function GetOutput
{
    ## Create a buffer to receive the response
    $buffer = new-object System.Byte[] 1024
    $encoding = new-object System.Text.AsciiEncoding
    $outputBuffer = ""
    $foundMore = $false
    $script:timeOut = $false
    ## Read all the data available from the stream, writing it to the
    ## output buffer when done.
    do
    {
        ## Allow data to buffer for a bit
        # start-sleep -m 1000
        ## Read what data is available
        $foundmore = $false
        $networkstream.ReadTimeout = 3000
        do
        {
            try
            {
                $script:timeOut = $false
                $read = $networkstream.Read($buffer, 0, 1024)
                if($read -gt 0)
                {
                    $foundmore = $true
                    $outputBuffer += ($encoding.GetString($buffer, 0, $read))

                    if($buffer[8] -eq 114) {
                        write-verbose 'SMB1 negotiate response'
                        $script:IsSMB1 = $true
                        write-host ' SMBV1 Negotiated Dialect   : ' $dialect[([System.BitConverter]::ToString($buffer[37]))]   -ForegroundColor green
                        $script:SMBVersion1 = $dialect[([System.BitConverter]::ToString($buffer[37]))]
                    }
                    else{
                        write-verbose 'SMB2 negotiate response'
                        $script:IsSMB1 = $false
                        $script:IsSMB2 = $true

                        $smb = ([System.BitConverter]::ToString($buffer[73..72]).Replace("-", ""))
                        $script:SMBSigning = ([System.BitConverter]::ToString($buffer[71..70]).Replace("-", ""))
                        $script:StartupTime = ([datetime]::fromfiletime(([bitconverter]::ToInt64($buffer[116..123],0))))
                       
                        if($smb -eq '02FF') {
                               write-verbose ' SMBV2 Negotiated Dialect   :  SMB 2.??? Wilcard (SMB V2 response)' -ForegroundColor yellow
                               $script:SMBVersion2 = '2.???'
                        }
                        elseif($smb -eq '0202') {
                               write-host ' SMBV2 Negotiated Dialect   :  SMB 2.002' -ForegroundColor green
                               $script:SMBVersion2 = '2.002'
                        }
                        elseif($smb -eq '0210') {
                               write-host ' SMBV2 Negotiated Dialect   :  SMB 2.1' -ForegroundColor green
                               $script:SMBVersion2 = '2.1'
                        }
                        elseif($smb -eq '0300') {
                               write-host ' SMBV2 Negotiated Dialect   :  SMB 3.0' -ForegroundColor green
                               $script:SMBVersion2 = '3.0'
                        }
                        elseif($smb -eq '0302') {
                               write-host ' SMBV2 Negotiated Dialect   :  SMB 3.2' -ForegroundColor green
                               $script:SMBVersion2 = '3.2'
                        }
                        elseif($smb -eq '0311') {
                               write-host ' SMBV2 Negotiated Dialect   :  SMB 3.11' -ForegroundColor green
                               $script:SMBVersion2 = '3.11'
                        }
                        else {
                               write-host " SMBV2 Negotiated Dialect   :  Unknown SMB 2 or 3 dialect ($smb)" -ForegroundColor magenta
                               $script:SMBVersion2 = 'Unknown'
                        }
                    }
               }
            } 
            catch
            { 
                # detect timeout to get response <> tcp Connection error
                if (-not $outputBuffer.Length) {$script:timeOut = $true}

                if ($script:timeOut -eq $true)
                {
                    $script:SMBVersion1 = 'TimeOut'
                    #$script:SMBVersion2 = 'TimeOut'
                }
                else{
                    $foundMore = $false; $read = 0 
                }
            }
         } while($read -gt 0)
         #} while($networkstream.DataAvailable)

    } while($foundmore)

    if ($outputBuffer.Length) {
        #write-host '$outputBuffer.Length:' $outputBuffer.Length
    }
    else{
        write-host " Not any requested dialects found on this host. Timeout: $script:timeOut" -ForegroundColor Magenta
    }
    #region Advanced output
    # Advanced output if -verbose
        if($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
        write-verbose $outputBuffer
        write-host '==============================================================================='
        write-host 'Negotiate response   -   OutputBuffer length:' $outputBuffer.Length
        write-host '==============================================================================='
        write-host '[0..3]    ' ([System.BitConverter]::ToString($buffer[0..3]))
        write-host '[4..7]    ' ([System.BitConverter]::ToString($buffer[4..7])) '' -NoNewline
        write-host $encoding.GetString($buffer[4..7]) '                                SMBIdentifier' -ForegroundColor Cyan
        # SMB negotiate 1 or 2


        #write-host 'Avant smbv1: ' $script:IsSMB1 -ForegroundColor Magenta
        if($IsSMB1){
            write-host '[8]       ' ([System.BitConverter]::ToString($buffer[8]))  '' -NoNewline
            write-host    $encoding.GetString($buffer[8]) '                                           Command' -ForegroundColor Cyan
            write-host '[9..10]   ' ([System.BitConverter]::ToString($buffer[9..10])) '                                          Status code'
            write-host '[11..12]  ' ([System.BitConverter]::ToString($buffer[11..12])) '                                          Status code suite'
            write-host '[13]      ' ([System.BitConverter]::ToString($buffer[13]))  '                                             Flag'
            write-host '[14..15]  ' ([System.BitConverter]::ToString($buffer[14..15]))  '                                          Flag2'
            write-host '[16..23]  ' ([System.BitConverter]::ToString($buffer[16..23]))  '                        PIDHigh'
            write-host '[24..25]  ' ([System.BitConverter]::ToString($buffer[24..25]))  '                                          SecuritySignature'  
            write-host '[26..27]  ' ([System.BitConverter]::ToString($buffer[26..27]))  '                                          Unused' 
            write-host '[28..29]  ' ([System.BitConverter]::ToString($buffer[28..29]))  '                                          TreeID'
            write-host '[30..31]  ' ([System.BitConverter]::ToString($buffer[30..31]))  '                                          ProcessID'     
            write-host '[32..33]  ' ([System.BitConverter]::ToString($buffer[32..33]))  '                                          UserID'         
            write-host '[34..35]  ' ([System.BitConverter]::ToString($buffer[34..35]))  '                                          MultiplexID'        
   
            # Dialect SMB V1
            write-host '[36]      ' ([System.BitConverter]::ToString($buffer[36])) '                                             WordCount (0x11)'
            write-host '[37..38]  ' ([System.BitConverter]::ToString($buffer[37..38]))  '' -NoNewline
            write-host    ([System.BitConverter]::ToString($buffer[37])) '                                       DialectIndex (SMB V1)' -ForegroundColor Cyan

            write-host '[39]      ' ([System.BitConverter]::ToString($buffer[39])) '                                             Security mode'
            write-host '[40..41]  ' ([System.BitConverter]::ToString($buffer[40..41])) '                                          MaxMpxCount'
            write-host '[42..43]  ' ([System.BitConverter]::ToString($buffer[42..43])) '                                          MaxNumberVcs'
            write-host '[44..47]  ' ([System.BitConverter]::ToString($buffer[44..47])) '                                    MaxBufferSize'
            write-host '[48..51]  ' ([System.BitConverter]::ToString($buffer[48..51])) '                                    MaxRawSize'
            write-host '[52..55]  ' ([System.BitConverter]::ToString($buffer[52..55]))  '                                    SessionKey'
            write-host '[56..59]  ' ([System.BitConverter]::ToString($buffer[56..59]))  '                                    Capabilities'
            write-host '[60..67]  ' ([System.BitConverter]::ToString($buffer[60..67]))   '' -NoNewline
            write-host '                        SystemTime:' ([datetime]::fromfiletime(([bitconverter]::ToInt64($buffer[60..67],0)))) -ForegroundColor Cyan
            write-host '[68..69]  ' ([System.BitConverter]::ToString($buffer[68..69])) '                                          ServerTimeZone '
            write-host '[70]      ' ([System.BitConverter]::ToString($buffer[70])) '                                             ChallengeLength'
            write-host '[71..72]  ' ([System.BitConverter]::ToString($buffer[71..72])) '                                          ByteCount (variable length below)'
            write-host '[73..88]  ' ([System.BitConverter]::ToString($buffer[73..88]))  '' -NoNewline                             
            write-host    $encoding.GetString($buffer[73..88])  -ForegroundColor Cyan
            write-host '[89..107] ' ([System.BitConverter]::ToString($buffer[89..107]))
            write-host '[108..123]' ([System.BitConverter]::ToString($buffer[108..123]))
        }
        else{
            # SMB V2 format
            #write-host '====== SMB V2 format'
            write-host '[8..9]    ' ([System.BitConverter]::ToString($buffer[8..9]))  '' -NoNewline
            write-host    $encoding.GetString($buffer[8..9]) '                                        StructureSize' -ForegroundColor Cyan
            write-host '[10..11]  ' ([System.BitConverter]::ToString($buffer[10..11])) '                                           CreditCharge'
            write-host '[12..15]  ' ([System.BitConverter]::ToString($buffer[12..15])) '                                     Status'
            write-host '[16..17]  ' ([System.BitConverter]::ToString($buffer[16..17])) '                                           Negotiate'
            write-host '[18..19]  ' ([System.BitConverter]::ToString($buffer[18..19])) '                                           Credit'
            write-host '[20..23]  ' ([System.BitConverter]::ToString($buffer[20..23])) '                                     Flags'
            write-host '[24..27]  ' ([System.BitConverter]::ToString($buffer[24..27])) '                                     NextCommand'
            write-host '[28..35]  ' ([System.BitConverter]::ToString($buffer[28..35])) '                         MessageID'
            write-host '[36..39]  ' ([System.BitConverter]::ToString($buffer[36..39])) '                                     ProcessID'
            write-host '[40..43]  ' ([System.BitConverter]::ToString($buffer[40..43])) '                                     TreeID'
            write-host '[44..51]  ' ([System.BitConverter]::ToString($buffer[44..51])) '                         SessionID'
            write-host '[52..67]  ' ([System.BitConverter]::ToString($buffer[52..67])) ' Signature'
            write-host '[68..69]  ' ([System.BitConverter]::ToString($buffer[68..69])) '                                           StructureSize'
            # signing SMB V2
            write-host '[70..71]  ' ([System.BitConverter]::ToString($buffer[70..71]))   '' -NoNewline
            write-host ([System.BitConverter]::ToString($buffer[71..70]).Replace("-", "")) '                                      SecurityMode SIGNING_ENABLED(1), SIGNING_REQUIRED(2)'  -ForegroundColor Cyan

            # Dialect SMB V2
            write-host '[72..73]  ' ([System.BitConverter]::ToString($buffer[72..73]))   '' -NoNewline
            write-host ([System.BitConverter]::ToString($buffer[73..72]).Replace("-", "")) '                                      DialectRevision (SMB V2)'  -ForegroundColor Cyan
            write-host '[74..75]  ' ([System.BitConverter]::ToString($buffer[74..75]))  '                                           NegotiateContextCount/Reserved'
            write-host '[76..91]  ' ([System.BitConverter]::ToString($buffer[76..91]))  ' ServerGuid'
            write-host '[92..95]  ' ([System.BitConverter]::ToString($buffer[92..95]))  '                                     Capabilities'
            write-host '[96..99]  ' ([System.BitConverter]::ToString($buffer[96..99]))  '                                     MaxTransactSize'
            write-host '[100..103]' ([System.BitConverter]::ToString($buffer[100..103]))  '                                     MaxReadSize'
            write-host '[104..107]' ([System.BitConverter]::ToString($buffer[104..107]))  '                                     MaxWriteSize'
            # Systemtime
            write-host '[108..115]' ([System.BitConverter]::ToString($buffer[108..115]))   '' -NoNewline
            write-host '                         SystemTime       :' ([datetime]::fromfiletime(([bitconverter]::ToInt64($buffer[108..115],0)))) -ForegroundColor Cyan
            # StartupTime
            write-host '[116..123]' ([System.BitConverter]::ToString($buffer[116..123]))   '' -NoNewline
            write-host '                         ServerStartupTime:' ([datetime]::fromfiletime(([bitconverter]::ToInt64($buffer[116..123],0)))) -ForegroundColor Cyan
            $ServerStartupTime = ([datetime]::fromfiletime(([bitconverter]::ToInt64($buffer[116..123],0))))
        }
        write-host "[124..$($outputBuffer.Length)]" ([System.BitConverter]::ToString($buffer[124..($outputBuffer.Length)]))
        write-host '==============================================================================='
        #endregion

    }
    
}
# End function GetOutput


#region Main

$script:TCPConnected = $false



if($SMBV1){
    #write-host 'Search SMBV1 only' -ForegroundColor cyan
    $script:IsSMB1 = 'Not reachable'
    $script:SMBVersion1 = 'Not reachable'
    $script:IsSMB2 = 'na'
    $script:SMBVersion2 = 'na'
    $script:SMBSigning = 'na'
    $script:StartupTime = 'na'
}
else{
    $script:IsSMB1 = 'Unknown'
    $script:SMBVersion1 = 'Unknown'
    $script:IsSMB2 = 'Not reachable'
    $script:SMBVersion2 = 'Not reachable'
    $script:SMBSigning = 'Unknown'
    $script:StartupTime = 'Unknown'
}



# dialects windows 10
$dialect = "PC NETWORK PROGRAM 1.0","LANMAN1.0","Windows for Workgroups 3.1a","LM1.2X002","LANMAN2.1","NT LM 0.12","SMB 2.002","SMB 2.???"

# First SMB negotiate packet

[Byte[]] $SmbNegotiatePacket =
0x00,0x00,0x00,0x9b,                          # NetBIOS Session 
0xff,0x53,0x4d,0x42,                          # Server Component: SMB
0x72,                                         # SMB Command: Negotiate Protocol
0x00,0x00,0x00,0x00,                          # NT Status: STATUS_SUCCESS
0x18,                                         # Flags: Operation 0x18
0x53,0xc8,                                    # Flags2: Sub 0xc853
0x00,0x00,                                    # Process ID High (normal value should be 0x00,0x00)
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      # Signature
0x00,0x00,                                    # Reserved
0xff,0xff,                                    # Tree ID
0xff,0xfe,                                    # Process ID
0x00,0x00,                                    # User ID
0x00,0x00,                                    # Multiplex ID
0x00,                                         # Negotiate Protocol Request: Word Count (WCT)
0x78,0x00,                                    # Byte Count (BCC)
0x02,0x50,0x43,0x20,0x4e,0x45,0x54,0x57,0x4f,0x52,0x4b,0x20,0x50,0x52,0x4f,0x47,0x52,0x41,0x4d,0x20,0x31,0x2e,0x30,0x00, # Requested Dialects: PC NETWORK PROGRAM 1.0
0x02,0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x31,0x2e,0x30,0x00,         # Requested Dialects: LANMAN1.0
0x02,0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x20,0x66,0x6f,0x72,0x20,0x57,0x6f,0x72,0x6b,0x67,0x72,0x6f,0x75,0x70,0x73,0x20,0x33,0x2e,0x31,0x61,0x00, # Requested Dialects: Windows for Workgroups 3.1a
0x02,0x4c,0x4d,0x31,0x2e,0x32,0x58,0x30,0x30,0x32,0x00,         # Requested Dialects: LM1.2X002
0x02,0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x32,0x2e,0x31,0x00,         # Requested Dialects: LANMAN2.1
0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00,    # Requested Dialects: NT LM 0.12
0x02,0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00,         # Requested Dialects: SMB 2.002
0x02,0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00          # Requested Dialects: SMB 2.???


# Second SMB negotiate packet, use only in case of wilcard answer after the first negotiate packet ( SMB 2.??? Wilcard (SMB V2 response) )

[Byte[]] $Smb2NegotiatePacket =
0x00,0x00,0x00,0xAE,                      # Zero + Length
0xFE,0x53,0x4D,0x42,                      # SMB
0x40,0x00,                                # StructureSize
0x00,0x00,                                #
0x00,0x00,                                # Status
0x00,0x00,
0x00,0x00,                                # Negotiate
0x00,0x00,                                # Credit
0x00,0x00,0x00,0x00,                      # Flags
0x00,0x00,0x00,0x00,                      # Next Command
0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  # MessageId
0xFF,0xFE,0x00,0x00,                      # ProcessId
0x00,0x00,0x00,0x00,                      # TreeId
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  # SessionId
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  # Signature
0x24,0x00,                                # CNegotiate: StructureSize 36 (0x24)
0x05,0x00,                                # DialectCount
0x01,0x00,                                # SecurityMode
0x00,0x00,                                # Reserved
0x7F,0x00,0x00,0x00,                      # Capabilities
#0xDB,0x0F,0x6B,0xE3,0x41,0x51,0xE8,0x11,0xA7,0x15,0xB0,0x5A,0xDA,0xE4,0x7A,0x92,  # Client Guid
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  # Client Guid not necessary  0
0x70,0x00,0x00,0x00,0x02,0x00,0x00,0x00,  # ClientStartime  01/01/1601
0x02,0x02,                                # Dialects: 514 (0x202)
0x10,0x02,                                # Dialects: 528 (0x210)
0x00,0x03,                                # Dialects: 768 (0x300)
0x02,0x03,                                # Dialects: 770 (0x302)
0x11,0x03,                                # Dialects: 785 (0x311)
0x00,0x00,0x01,0x00,0x26,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x20,0x00,0x01,0x00,0x73,0x87,0x40,0x06,0xD6,      # Padding
0xA8,0x82,0xB2,0xDB,0x02,0x22,0x2E,0x4A,0x71,0x8D,0xBB,0xAE,0xA4,0x41,0xB7,0x1A,0xCC,0x08,0x8B,0xE8,0x64,      # Padding
0x42,0x14,0x3A,0x60,0xB4,0xEA,0x00,0x00,0x02,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x02,0x00,0x01,0x00  # Padding


# SMB1 dialect only

[Byte[]] $Smb1NegotiatePacket =
0x00,0x00,0x00,0x85,                          # NetBIOS Session: Total packet size - 4
0xff,0x53,0x4d,0x42,                          # Server Component: SMB
0x72,                                         # SMB Command: Negotiate Protocol
0x00,0x00,0x00,0x00,                          # NT Status: STATUS_SUCCESS
0x18,                                         # Flags: Operation 0x18
0x53,0xc8,                                    # Flags2: Sub 0xc853
0x00,0x00,                                    # Process ID High (normal value should be 0x00,0x00)
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      # Signature
0x00,0x00,                                    # Reserved
0xff,0xff,                                    # Tree ID
0xff,0xfe,                                    # Process ID
0x00,0x00,                                    # User ID
0x00,0x00,                                    # Multiplex ID
0x00,                                         # Negotiate Protocol Request: Word Count (WCT)
0x62,0x00,                                    # Byte Count (BCC)
0x02,0x50,0x43,0x20,0x4e,0x45,0x54,0x57,0x4f,0x52,0x4b,0x20,0x50,0x52,0x4f,0x47,0x52,0x41,0x4d,0x20,0x31,0x2e,0x30,0x00, # Requested Dialects: PC NETWORK PROGRAM 1.0
0x02,0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x31,0x2e,0x30,0x00,         # Requested Dialects: LANMAN1.0
0x02,0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x20,0x66,0x6f,0x72,0x20,0x57,0x6f,0x72,0x6b,0x67,0x72,0x6f,0x75,0x70,0x73,0x20,0x33,0x2e,0x31,0x61,0x00, # Requested Dialects: Windows for Workgroups 3.1a
0x02,0x4c,0x4d,0x31,0x2e,0x32,0x58,0x30,0x30,0x32,0x00,         # Requested Dialects: LM1.2X002
0x02,0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x32,0x2e,0x31,0x00,         # Requested Dialects: LANMAN2.1
0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00     # Requested Dialects: NT LM 0.12


$ip = $computername

if($SMBV1){
    write-verbose 'Negotiating SMBV1 only' 
    write-host 'Negotiating SMBV1 dialect on: ' $ip -ForegroundColor cyan 

    PushToTcpPort -bytearray $Smb1NegotiatePacket -ipaddress $ip -port 445
}
else{
    write-verbose 'Negotiating SMBV1 and SMBV2' 
    write-host 'Negotiating SMBV2 dialect on: ' $ip -ForegroundColor cyan 

    PushToTcpPort -bytearray $SmbNegotiatePacket -bytearray2 $Smb2NegotiatePacket -ipaddress $ip -port 445
    if($script:TCPConnected) { 
        if(-not $script:IsSMB1){
            write-host 'Negotiating SMBV1 dialect on: ' $ip -ForegroundColor cyan 
            PushToTcpPort -bytearray $Smb1NegotiatePacket -ipaddress $ip -port 445
        }
        else{
            $script:IsSMB2 = $false
            $script:SMBVersion2 = 'na'
        }
    }
}


if($SMBV1){
    $script:SMBSigning = 'na'
    $script:StartupTime = 'na'
}

if($script:SMBVersion1 -eq 'Not reachable' -or $script:SMBVersion1 -eq 'TimeOut' -or $script:SMBVersion1 -eq 'Unknown')
{
    $script:IsSMB1 = $script:SMBVersion1
}
if($script:TCPConnected){
    if($script:SMBVersion1 -eq 'TimeOut'){
        $script:IsSMB1 = $false
        $script:SMBVersion1 = 'na'
    }
}

# output object

if($SMBV1){
        $Result = New-Object PSObject
        $Result | add-member Noteproperty Domain $trusteddomain
        $Result | add-member Noteproperty Host $computername                      
        $Result | add-member Noteproperty IsSmbV1 $script:IsSMB1
        $Result | add-member Noteproperty DialectSmbV1 $script:SMBVersion1
}
else{
        $Result = New-Object PSObject
        $Result | add-member Noteproperty Domain $trusteddomain
        $Result | add-member Noteproperty Host $computername                        
        $Result | add-member Noteproperty IsSmbV1 $script:IsSMB1
        $Result | add-member Noteproperty DialectSmbV1 $script:SMBVersion1
        $Result | add-member Noteproperty IsSmbV2 $script:IsSMB2            
        $Result | add-member Noteproperty DialectSmbv2 $script:SMBVersion2
        $Result | add-member Noteproperty Signing $script:SMBSigning
        $Result | add-member Noteproperty ServerStartupTime $script:StartupTime
}

$Result

#endregion