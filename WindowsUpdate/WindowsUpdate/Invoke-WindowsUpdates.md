# Invoke-WindowsUpdates

## SYNOPSIS
This function will Install all availible updates that are detected thought the windows update api.

## SYNTAX

```
Invoke-WindowsUpdate
```

## DESCRIPTION
This function will downlaod the PSWindowsUpdate Module and use the Install-WindowsUpdates function to install all availible updates. 

## EXAMPLES

## PARAMETERS

### -Reboot
Used to allow system to reboot upon finishing installing updates.
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

Creation Date:  2/22/2022

Purpose/Change: Initial function development 


## RELATED LINKS