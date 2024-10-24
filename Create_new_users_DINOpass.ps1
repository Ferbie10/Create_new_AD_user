# Import the Active Directory module
Import-Module ActiveDirectory

# Path to the CSV file
$csvPath = "~\Desktop\New Users.csv"

# Function to generate a password that meets complexity requirements
function Generate-Password {
    # Generate a base password using DinoPass API
    $url = "http://www.dinopass.com/password/simple"
    $password = Invoke-RestMethod -Uri $url

    # Modify the first character to uppercase if it's lowercase
    if ($password[0] -cmatch '[a-z]') {
        $password = ([string]$password[0]).ToUpper() + $password.Substring(1)
    }

    # Ensure password contains at least one lowercase letter
    if (-not ($password -cmatch '[a-z]')) {
        $password += [char](Get-Random -Minimum 97 -Maximum 123) # Append random lowercase letter
    }

    # Ensure password contains at least one digit
    if (-not ($password -cmatch '[0-9]')) {
        $password += [char](Get-Random -Minimum 48 -Maximum 58) # Append random digit
    }

    # Ensure password is at least 8 characters long
    while ($password.Length -lt 8) {
        $password += [char](Get-Random -Minimum 97 -Maximum 123) # Add random lowercase letters to meet length
    }

    return $password
}

# Get the current date to append to the CSV file name
$currentDate = Get-Date -Format "yyyy-MM-dd"
$outputFilePath = "~\Desktop\new-users-$currentDate.csv"

# Read the CSV file, now with the additional 'SourceUser' column
$users = Import-Csv -Path $csvPath -Header FirstName, LastName, SourceUser

# Initialize an array to hold user creation details
$newUsers = @()

# Loop through each user
foreach ($user in $users) {
    # Create the username using the specified format (first initial + last name)
    $firstInitial = $user.FirstName.Substring(0,1).ToLower()
    $lastName = $user.LastName.ToLower()
    
    # Check if the source user's username ends with '-g'
    if ($user.SourceUser -like '*-g') {
        # If the source user has '-g', append it to the new username
        $username = "$firstInitial$lastName-g"
        $changePasswordAtLogon = $false  # Do not require password change on login
        $middleInitial = 'G'  # Set middle initial as 'G'
    } else {
        # Otherwise, use just the first initial and last name
        $username = "$firstInitial$lastName"
        $changePasswordAtLogon = $true  # Require password change on first login
        $middleInitial = ''  # No middle initial or leave it as needed
    }

    # Generate a random password
    $password = Generate-Password

    # Copy attributes from the source user specified in the CSV
    $sourceAttributes = Get-ADUser -Identity $user.SourceUser -Properties *

    # Get the source user's Distinguished Name (DN) and extract the OU
    $sourceOU = ($sourceAttributes.DistinguishedName -replace '^.*?[,]', '') # Extracts the OU from the DN

    # Create the new user details
    $newUserParams = @{
        SamAccountName = $username
        UserPrincipalName = "$username@yourdomain.com" # Update with your domain
        Name = "$($user.FirstName) $($user.LastName)"
        GivenName = $user.FirstName
        Surname = $user.LastName
        DisplayName = "$($user.FirstName) $middleInitial. $($user.LastName)"  # Include middle initial if set
        AccountPassword = (ConvertTo-SecureString $password -AsPlainText -Force)
        Enabled = $true
        Path = $sourceOU # Use the same OU as the source user
        PasswordNeverExpires = $false  # Ensure password expiration policy applies
        ChangePasswordAtLogon = $changePasswordAtLogon # Force password change at first login if not -g
        Initials = $middleInitial  # Add middle initial
        # Copy other properties as needed
        Title = $sourceAttributes.Title
        Department = $sourceAttributes.Department
    }

    # Create the new Active Directory user
    try {
        New-ADUser @newUserParams

        # Output result with first and last names
        Write-Host "$($user.FirstName) $($user.LastName) Created user: $username with password: $password"

        # Add the newly created user's details to the array
        $newUsers += [PSCustomObject]@{
            FirstName  = $user.FirstName
            LastName   = $user.LastName
            Username   = $username
            Password   = $password
        }

        # Get the new user's distinguished name for group membership
        $newUserDN = Get-ADUser -Identity $username

        # Copy group memberships (memberOf attribute) from the source user
        $sourceGroups = $sourceAttributes.memberOf

        if ($sourceGroups) {
            foreach ($group in $sourceGroups) {
                try {
                    Add-ADGroupMember -Identity $group -Members $newUserDN
                } catch {
                    Write-Host "Failed to add $username to group: $group. Error: $_"
                }
            }
        } else {
            Write-Host "$($user.FirstName) $($user.LastName) has no groups to copy from $user.SourceUser"
        }

    } catch {
        Write-Host "Failed to create user: $username. Error: $_"
    }
}

# Export the new users' details to a CSV file
$newUsers | Export-Csv -Path $outputFilePath -NoTypeInformation

Write-Host "New users' details exported to $outputFilePath"
