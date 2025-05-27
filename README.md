# DCFTokenGrabber - Microsoft OAuth 2.0 Device Code Flow Toolkit (PowerShell)
This PowerShell script provides a fully interactive way to authenticate against Microsoft services using the OAuth 2.0 Device Code Flow. It allows you to simulate how different public client applications (like Microsoft Office, Azure CLI, Azure Portal etc.) interact with various Microsoft resources (e.g. Graph API, Azure Management, Outlook) by authenticating and retrieving access and refresh tokens.

## Features
- Interactive client and resource selection menu
- Secure Device Code authentication using browser
- Retrieves and displays access tokens and refresh tokens
- Decodes JWT tokens for inspection (e.g. scopes, expiry, tenant ID)
- Supports common Microsoft services like Graph API, Outlook, Key Vault, Azure Portal, etc.
- Ideal for testing, learning, or reverse engineering public client capabilities

## Included Functions
| Function Name             | Purpose                                                                 |
|---------------------------|-------------------------------------------------------------------------|
| `Show-ClientMenu`         | Lets the user choose from a list of Microsoft public client applications |
| `Show-AppMenu`            | Lets the user choose a resource (API) to request access to              |
| `Request-DeviceCode`      | Requests a device code from Microsoft Identity platform                 |
| `Wait-ForToken`           | Polls the token endpoint until the user completes authentication        |
| `Decode-JwtToken`         | Decodes and parses JWT access tokens into readable JSON                 |
| `Start-AuthenticationFlow`| Orchestrates the full authentication and token retrieval process        |


## Requirements
- PowerShell 5.1+ or PowerShell Core
- Internet connection
- Microsoft account or Azure AD account

## Usage
```powershell
# Load the PowerShell script
. .\DCFTokenGrabber.ps1

# Run the main function:
Start-AuthenticationFlow

# Select the public client you'd like to simulate (e.g. Microsoft Teams).
Nr Name
-- ----
 1 Microsoft Office
 2 Microsoft Outlook
 3 Office 365 SharePoint Online
 4 Azure Portal
 5 Microsoft Azure CLI
 6 Microsoft Azure PowerShell
 7 Microsoft Office 365 Portal
 8 Windows Azure Active Directory
 9 Office Exchange Online

# Choose the resource you want access to (e.g. Microsoft Graph).
Nr Name
-- ----
 1 Microsoft Graph
 2 Microsoft Office
 3 Azure Keyvault
 4 Azure Resource Manager

# Open the verification URL in your browser and enter the displayed device code.

# Once authenticated, the script will display:
- Access Token
- Refresh Token (if issued)
- Tenant ID
- Authenticated user's UPN
- Token scopes and expiry
``` 


## Example Output
```powershell
[*] URL to authenticate:
https://microsoft.com/devicelogin

[*] Device Code:
ABCD-EFGH

[+] Login successful!
[+] Access Token:
<token here>

[+] Tenant ID:
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

[+] UserPrincipalName:
user@contoso.com

[+] Scopes for Access Token:
User.Read Mail.Read

[+] Token valid until:
2025-05-25 22:43:10
``` 


## Disclaimer
This tool is for educational and testing purposes only. It does not handle confidential clients or use client secrets. Use responsibly and in accordance with Microsoft's terms of use.

## License
This project is released under the MIT License.

## Contributing
Contributions and pull requests are welcome! Feel free to fork, improve, and submit suggestions via GitHub issues or PRs.

