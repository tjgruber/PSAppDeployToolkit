﻿#-----------------------------------------------------------------------------
#
# MARK: Add-ADTSessionStartingCallback
#
#-----------------------------------------------------------------------------

function Add-ADTSessionStartingCallback
{
    <#
    .SYNOPSIS
        Adds a callback to be executed when the ADT session is starting.

    .DESCRIPTION
        The Add-ADTSessionStartingCallback function registers a callback command to be executed when the ADT session is starting. This function sends the callback to the backend function for processing.

    .PARAMETER Callback
        The callback command(s) to be executed when the ADT session is starting.

    .INPUTS
        None

        You cannot pipe objects to this function.

    .OUTPUTS
        None

        This function does not return any output.

    .EXAMPLE
        Add-ADTSessionStartingCallback -Callback $myCallback

        This example adds the specified callback to be executed when the ADT session is starting.

    .NOTES
        An active ADT session is required to use this function.

        Tags: psadt
        Website: https://psappdeploytoolkit.com
        Copyright: (C) 2024 PSAppDeployToolkit Team (Sean Lillis, Dan Cunningham, Muhammad Mashwani, Mitch Richters, Dan Gough).
        License: https://opensource.org/license/lgpl-3-0

    .LINK
        https://psappdeploytoolkit.com
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.CommandInfo[]]$Callback
    )

    # Send it off to the backend function.
    try
    {
        if ($PSCmdlet.ShouldProcess($Callback, 'Invoke-ADTSessionCallbackOperation -Type Starting -Action Add'))
        {
            Invoke-ADTSessionCallbackOperation -Type Starting -Action Add @PSBoundParameters
        }
    }
    catch
    {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
