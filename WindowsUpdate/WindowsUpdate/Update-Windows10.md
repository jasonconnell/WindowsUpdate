# Update-Windows10

## SYNOPSIS
This function will attempt to fully automate the installation of Windows 10 feature updates.

## SYNTAX

```
Get-DownloadSpeed
```

## DESCRIPTION
This function will attempt to fully automate the installation of Windows 10 feature updates.
## EXAMPLES

## PARAMETERS

### -CopyLogs
Specifies the output of where the logs for the install will be stored.
```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UpdateTool
This can be used to specify a different installer executable.
```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: 'https://download.microsoft.com/download/2/b/b/2bba292a-21c3-42a6-8123-98265faff0b6/Windows10Upgrade9252.exe'
Accept pipeline input: False
Accept wildcard characters: False
```

### -BackupUserProfile
This will preform a backup of user profile data before starting the update process.
```yaml
Type: Switch
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FreeSpaceThreshold
This can be used to specify a new disk threshold. Default is 20GB.
```yaml
Type: int[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: 20
Accept pipeline input: False
Accept wildcard characters: False
```

### -ISO
This can be used to specify an ISO install method. Requires an ISO to be specifed.
```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NoReboot
This can be used to supress reboots during the installation. 
```yaml
Type: Switch
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
Version:        1.0

Author:         Jason Connell

Creation Date:  3/19/2021

Purpose/Change: Initial function development 


## RELATED LINKS