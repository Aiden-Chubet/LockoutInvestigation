## Get source of lockout events from every DC
Function Get-DCLockoutSummary {
    $LogonDCs = 'DC1','DC2','101ES-DC1'
    Foreach ($DC in $LogonDCs)
        {
        $filterHash = @{LogName = "Security"; Id = 4740; StartTime = (Get-Date).AddDays(-10)}
        $lockoutEvents = Get-WinEvent -ComputerName $DC -FilterHashTable $filterHash -MaxEvents 1000 -ErrorAction SilentlyContinue
        $lockoutEvents | Select-Object @{Name = "LockedUser"; Expression = {$_.Properties[0].Value}}, `
                            @{Name = "SourceComputer"; Expression = {$_.Properties[1].Value}}, `
                            @{Name = "DomainController"; Expression = {$_.Properties[4].Value}}, TimeCreated
        }
    }
    ## Test function
    Get-DCLockoutSummary

 
    
## Get details of lockout events from Caller Server
Function Get-ServerLockoutDetails {
    $ServerList = 'APP01','FP01','101ES-DC1','DC2'
    Foreach ($Server in $ServerList)
        {
            $filterHash2 = @{LogName = "Security"; Id = 4625; StartTime = (Get-Date).AddDays(-3)}
            $lockoutEvents2 = Get-WinEvent -ComputerName $Server -FilterHashTable $filterHash2 -MaxEvents 25 -ErrorAction 0
            $lockoutEvents2 | Select-Object @{Name = "LockedUserName"; Expression = {$_.Properties[5].Value}}, `
                                    @{Name = "TimeStamp"; Expression = {$_.TimeCreated}}, `
                                    @{Name = "LogonType"; Expression = {$_.Properties[10].Value}}, `
                                    @{Name = "LogonProcessName"; Expression = {$_.Properties[11].Value}}, `
                                    @{Name = "ProcessName"; Expression = {$_.Properties[18].Value}}
        }
    }
    ## Test function
    Get-ServerLockoutDetails    



## Get details of lockout events from Caller Computer
Function Get-ComputerLockoutDetails {
    $computerName = Read-Host "Enter the computer name for details"
    
            $filterHash2 = @{LogName = "Security"; Id = 4625; StartTime = (Get-Date).AddDays(-3)}
            $lockoutEvents2 = Get-WinEvent -ComputerName $computerName -FilterHashTable $filterHash2 -MaxEvents 25 -ErrorAction 0
            $lockoutEvents2 | Select-Object @{Name = "LockedUserName"; Expression = {$_.Properties[5].Value}}, `
                                    @{Name = "TimeStamp"; Expression = {$_.TimeCreated}}, `
                                    @{Name = "LogonType"; Expression = {$_.Properties[10].Value}}, `
                                    @{Name = "LogonProcessName"; Expression = {$_.Properties[11].Value}}, `
                                    @{Name = "ProcessName"; Expression = {$_.Properties[18].Value}}
    }
    ## Test function
    Get-ComputerLockoutDetails    



#Get a list of all users lockedout
Search-ADAccount -LockedOut | Select-Object Name,SamAccountName

#Unlock all lockedout users
Search-ADAccount -LockedOut | Unlock-ADAccount
