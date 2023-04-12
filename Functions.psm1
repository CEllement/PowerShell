Function Get-NTFSAnalysis
{
<#
.SYNOPSIS
Finds all folders where inheritance is diabled OR one or more ACEs have been explicity added
.DESCRIPTION
Given a path(s), it will recursively check all folders and return those where inheritance is disabled OR where inheritance is still enabled but permissions were explicitly changed and will list
the full path and the ACL for that folder. If column C is TRUE, then inheritance is broken, otherwise the ACL was changed either by adding more permissions (e.g. going from Write to Modify) or
adding another user and/or group in addition to the inherited permissions
.EXAMPLE
If you only have one path, you can pipe it to the function e.g. \\serverPath\ | Get-NTFSAnalysis -reportName "NTFSAnalysis" -Verbose. If you have two or more paths, you cannot pipe it
but rather you will need to list them all out as follows: Get-NTFSAnalysis -path "path1", "path2", "path..N" -reportName "NTFSAnalysis" -Verbose e.g. Get-NTFSAnalysis -path "\\serverPath\", 
"\\serverPath2\" -reportName "NTFSAnalysis" -Verbose.
#>
[CmdletBinding()]
Param(
[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
[string[]]$path,
[Parameter(Mandatory=$true)]
[string]$reportName
)
PROCESS
{
Write-Verbose "Locating all folders with inheritance disabled OR with explicit permissions applied given each path provided"
$outputPath = $reportName + ".csv"
$CustomResult = @()
Get-ChildItem $path -Recurse -Directory | ForEach-Object {
    try { # Get-Acl throws terminating errors, so wrap it in a try/catch block
        $_ | Get-Acl | 
            where { $_.AreAccessRulesProtected -or ($_.Access | where { $_.IsInherited -eq $false }) } | ForEach-Object {
            $CustomResult += [PSCustomObject] @{
            Path = Convert-Path $_.path
			ACL = (Get-ACL -Path $_.path).accesstostring
            "Inheritance Disabled" = $_.AreAccessRulesProtected
}}
    }
    catch {
        Write-Error $_
    }
   }
   $CustomResult | sort Path | export-csv c:\temp\$outputPath -NoTypeInformation
}
END
{
Write-Host "Please check C:temp for your csv report and for Errors.txt" -ForegroundColor Yellow
}
}

Function Get-UsersOnACL
{
<#
.SYNOPSIS
Locates individual user account(s) in the form of u* and it looks for four or five numbers and will also look for "a" accounts. "u" stands for "user" and it will end in "a" if it is an admin account.
.DESCRIPTION
It will locate all of the following: u00000, u00000a, u0000, u0000a, uu0000, uu0000a, uu00000 and uu00000a. You do not need the -Verbose parameter (it just gives more information). This will
find individual user accounts on file system folders since this is not best practice.
.EXAMPLE
If you only have one path, you can pipe it to the function e.g. \\serverPath\ | Get-UsersOnACL -reportName "UsersOnACL" -Verbose. If you have two or more paths, you cannot pipe it
but rather you will need to list them all out as follows: Get-UsersOnACL -path "path1", "path2", "path..N" -reportName "UsersOnACL" -Verbose e.g. Get-UsersOnACL -path "\\serverPath\", 
"\\serverPath2\" -reportName "UsersOnACL" -Verbose.
#>
[CmdletBinding()]
PARAM (
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string[]]$path,
    [Parameter(Mandatory=$true)]
    [string]$reportName
    )

PROCESS
{
Write-Verbose "Locating individual user accounts (including ""a"" accounts) on the path(s) provided, recursively"

$outputpath = $reportname + ".csv"
Dir $path -rec -dir -ErrorAction SilentlyContinue -ErrorVariable failederrors | ForEach-Object { Get-Acl -Path $_.FullName |
Where {$_.AccessToString -match "\b[uU]{1,2}\d{4,5}a?\b" |
Select @{Name="Path";E={Convert-Path $_.pspath}},AccessToString} | Export-Csv c:\temp\$outputpath -NoTypeInformation
$failederrors.exception | out-file c:\temp\FailedErrors.txt
}

END {
Write-Host "Please check your c:\temp folder for the .csv report and for FailedErrors.txt" -ForegroundColor Cyan
}
}

Function Find-WhereADGroupIsUsed
{
<#
.SYNOPSIS
Finds all folders an AD group is on the ACL for given: an AD group, a path to look under and a depth level
.DESCRIPTION
This function will search NAS folders recursively to find where an AD group is used. Two columns are returned if found, the path the AD group is contained in and the ACL for that folder. It also can check
where an AD group is NOT used by using the notUsed switch. As long as the account running the command has read access to the parent folder, it will find where the account is not used. This can
be useful, for e.g., when an admin group was removed from one or more folders.
.EXAMPLE
Find-WhereADGroupIsUsed -path "\\serverPath\" -group "Group A" -depth 3 -reportName GroupA_WhereUsed. If you have two paths you can combine as follows:
Find-WhereADGroupIsUsed -path "path1", "path2", "path..N" -reportName "reportName" -Verbose e.g. Find-WhereADGroupIsUsed -path "\\serverPath\", "\\serverPath2\" -group|
"Group B" -depth 2 -reportName "GroupB_WhereUsed" -Verbose. You can also search multiple groups at once for one or more paths. Just add it to an array with syntax @().
#>
[CmdletBinding()]
PARAM (
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string[]]$path,
    [Parameter(Mandatory=$true)]
    [string[]]$group,
    [Parameter(Mandatory=$true)]
    [string]$depth,
    [Parameter(Mandatory=$true)]
    [string]$reportName,
    [Parameter()]
    [switch]$notUsed = $false
    )

PROCESS
{
Write-Verbose "Finding all folders the given AD group has access to"

if ($notUsed) {
$outputpath = $reportname + ".csv"
dir $path -dir -ErrorAction SilentlyContinue -Depth $depth -ErrorVariable NoAccess | Where {$_.psiscontainer -eq "TRUE"} | ForEach-Object {get-acl $_.fullname} |
select @{Name='Path';E={convert-path $_.pspath}}, accesstostring | Select-String -notMatch $group | select @{Name = 'Path'; Expression = { (($_.line -split '@{Path=')[1] -split '; AccessToString=')[0] } },@{Name = 'ACL'; Expression = { (($_.line -split '; AccessToString=')[1] -split '}')[0] } } |
sort Path | export-csv C:\temp\$outputpath -NoTypeInformation
$NoAccess.exception | out-file c:\temp\NoAccess.txt
}

else {

$outputpath = $reportname + ".csv"
dir $path -dir -ErrorAction SilentlyContinue -Depth $depth -ErrorVariable NoAccess | Where {$_.psiscontainer -eq "TRUE"} | ForEach-Object {get-acl $_.fullname} |
select @{Name='Path';E={convert-path $_.pspath}}, accesstostring | Select-String $group | select @{Name = 'Path'; Expression = { (($_.line -split '@{Path=')[1] -split '; AccessToString=')[0] } },@{Name = 'ACL'; Expression = { (($_.line -split '; AccessToString=')[1] -split '}')[0] } } |
sort Path | export-csv C:\temp\$outputpath -NoTypeInformation
$NoAccess.exception | out-file c:\temp\NoAccess.txt
}
}

END {
Write-Host "Please check your c:\temp folder for the .csv report and for NoAccess.txt" -ForegroundColor Cyan
}
}

Function Get-FolderACLToParentACLComparison
{
<#
.SYNOPSIS
Finds all folders where the ACL does not match the current folder's parent folder ACL
.DESCRIPTION
Given a path, it will recursively check all folders and return those where the ACL is not equal to its parent. If true, it will list out the path, ACL and whether or not inheritance is diabled. If the csv file is
empty, that just means all sub-folders, given the depth level to check, all match the parent ACL.
.EXAMPLE
Get-FolderACLToParentACLComparison -Dir "\\serverPath\ParentFolder\" -depth 2 -reportName "ACL_Comparison" -Verbose
#>
[CmdletBinding()]
Param(
[Parameter(Mandatory=$true)]
[string[]]$Dir,
[Parameter(Mandatory=$true)]
[string]$reportName,
[Parameter()]
[string]$depth
)
PROCESS
{
Write-Verbose "Locating all folders whose ACL does not match its parent folder"

$outputPath = $reportName + ".csv"
$errorPath = $reportName + "_errors.txt"
#$parentPath = Get-ChildItem $Dir | select -expand psparentpath
#$parentACL = (Get-ACL-Path $parentPath).accesstostring
$CustomResult = @()
Get-ChildItem $Dir -Recurse -depth $depth -Directory -ErrorAction SilentlyContinue -ErrorVariable failederrors | select -ExpandProperty fullname | ForEach-Object {
	$parentPath = Split-Path -Path $_ -Parent
	$parentACL = (Get-ACL-Path $parentPath).accesstostring

	if ((Get-ACL $_).accesstostring -ne $parentACL) {
	$CustomResult += [PSCustomObject] @{
		Path = $_
		ACL = (Get-ACL-Path $_).accesstostring
		"Inheritance Disabled" = (Get-ACL $_).AreAccessRulesProtected
}
}
}
}
END {
$CustomResult | sort Path | export-csv c:\temp\$outputPath -NoTypelnformation
$failederrors.exception | out-file c:\temp\$errorPath
Write-Host "Please check C:\temp for your $outputPath and $errorPath report/errors" -ForegroundColor Cyan
}
}