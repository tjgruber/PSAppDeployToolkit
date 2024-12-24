﻿#-----------------------------------------------------------------------------
#
# MARK: Test-ADTUserIsBusy
#
#-----------------------------------------------------------------------------

function Test-ADTUserIsBusy
{
    <#
    .SYNOPSIS
        Tests whether the device's microphone is in use, the user has manually turned on presentation mode, or PowerPoint is running in either fullscreen slideshow mode or presentation mode.

    .DESCRIPTION
        Tests whether the device's microphone is in use, the user has manually turned on presentation mode, or PowerPoint is running in either fullscreen slideshow mode or presentation mode.

    .INPUTS
        None

        You cannot pipe objects to this function.

    .OUTPUTS
        System.Boolean

        Returns $true if the device's microphone is in use, the user has manually turned on presentation mode, or PowerPoint is running in either fullscreen slideshow mode or presentation mode, otherwise $false.

    .EXAMPLE
        Test-ADTUserIsBusy

        Tests whether the device's microphone is in use, the user has manually turned on presentation mode, or PowerPoint is running in either fullscreen slideshow mode or presentation mode, and returns true or false.

    .NOTES
        An active ADT session is NOT required to use this function.

        Tags: psadt
        Website: https://psappdeploytoolkit.com
        Copyright: (C) 2024 PSAppDeployToolkit Team (Sean Lillis, Dan Cunningham, Muhammad Mashwani, Mitch Richters, Dan Gough).
        License: https://opensource.org/license/lgpl-3-0

    .LINK
        https://psappdeploytoolkit.com
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Boolean])]
    param
    (
    )

    try
    {
        return ((Test-ADTMicrophoneInUse) -or (Get-ADTPresentationSettingsEnabledUsers) -or (Test-ADTPowerPoint))
    }
    catch
    {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
