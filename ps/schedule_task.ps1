$name = $(Read-Host -Prompt "Enter task name").Trim();
Write-Host "";
$time = $(Read-Host -Prompt "Enter task execution time (hh:mm)").Trim();
Write-Host "";
Get-LocalUser | Where-Object { $_.Enabled -eq $true } | Format-Table -AutoSize -Property Name, SID;
$user = $(Read-Host -Prompt "Enter user name").Trim();
Write-Host "";
$file = $(Read-Host -Prompt "Enter file name").Trim();
Write-Host "";
$argument = $(Read-Host -Prompt "Enter file arguments (optional)").Trim();
Write-Host "";
$level = $(Read-Host -Prompt "Run as administrator (optional) (yes)").Trim();
Write-Host "";
if ($name.Length -lt 1 -or $time.Length -lt 1 -or $user.Length -lt 1 -or $file.Length -lt 1) {
	Write-Host "Required parameters are missing";
} else {
	$exists = $null;
	$trigger = $null;
	$action = $null;
	$task = $null;
	try {
		$exists = Get-ScheduledTask | Where-Object { $_.TaskName -eq $name };
		if ($exists -ne $null) {
			Write-Host "Task already exists";
		} else {
			$trigger = New-ScheduledTaskTrigger -At $time -Once;
			if ($argument.Length -lt 1) {
				$action = New-ScheduledTaskAction -Execute $file;
			} else {
				$action = New-ScheduledTaskAction -Execute $file -Argument $argument;
			}
			if ($level -eq "yes") {
				# this cmdlet's exception cannot be caught, so this is a quick fix
				$task = Register-ScheduledTask -TaskName $name -Trigger $trigger -User $user -Action $action -Force -RunLevel Highest -ErrorAction SilentlyContinue;
			} else {
				$task = Register-ScheduledTask -TaskName $name -Trigger $trigger -User $user -Action $action -Force -ErrorAction SilentlyContinue;
			}
			if ($task -ne $null) {
				Write-Host "Task was scheduled successfully";
			} else {
				Write-Host "Cannot scheduled the task";
			}
		}
	} catch {
		Write-Host $_.Exception.InnerException.Message;
	} finally {
		if ($exists -ne $null) {
			$exists.Dispose();
		}
		if ($trigger -ne $null) {
			$trigger.Dispose();
		}
		if ($action -ne $null) {
			$action.Dispose();
		}
		if ($task -ne $null) {
			$task.Dispose();
		}
	}
}
