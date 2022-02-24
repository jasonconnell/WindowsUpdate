# Get-MissingUpdates

## SYNOPSIS
This function will query Windows Update for all availible updates and store in text document
## SYNTAX

```
Get-MissingUpdates
```

## DESCRIPTION
This function will query Windows Update for all availible updates. Default location is C:\windows\temp\missingupdates.txt

## EXAMPLES
Get-MissingUpdates -Path "C:\windows\Temp\Missingupdates.txt"

## PARAMETERS

### -Path
Specifies the output of where the Update document will be stored.
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