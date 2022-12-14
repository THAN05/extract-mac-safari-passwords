-- Exports Safari's saved passwords to a CSV file formatted for use with the csv converter in the mrc-converter-suite 
--
-- Copyright 2021 Mike Cappella (mike at cappella dot us)

use AppleScript version "2.5" -- runs on 10.11 (El Capitan) and later				
use scripting additions

-- The script requires at least version 12 of Safari
property minSafariVersion : 12
property maxSafariVersion : 15

set safariVersion to item 1 of Split(version of application "Safari", ".")

if safariVersion < minSafariVersion then
	display dialog "This script requires Safari version " & minSafariVersion & " or newer." & return & return & "The Get_Safari11_Passwords AppleScript in the Unsupported folder may work." buttons {"Ok"} default button "Ok"
	error number -128
end if

if safariVersion ≥ maxSafariVersion then
	display dialog "Safari version " & maxSafariVersion & " or newer can export keychain passwords as CSV" & return & return & "Open Safari's Preferences, go to the Passwords tab, unlock it, use the small pulldown menu at the bottom of the password list, and select the Export Passwords... item." buttons {"Ok"} default button "Ok"
	error number -128
end if

-- Languages such as Japanese require the script to be saved as UTF-16.
-- Including this symbol persuades Script Editor's Export to ensure this.
property forceUTF16encoding : "🍎"

-- Maximum amount of time to allow Safari to process password data
property extractionTimeout : 30 * 60 -- 30 minutes

-- Maximum number of tries (once per second) for reading password table row data.
-- It can take a few seconds for Safari to populate the password table, esp. when VoiceOver
-- is enabled, or the system is running slowly.
-- The table's row count is sampled until two consistent row counts are obtained, or maxAttempts
property maxAttempts : 10

-- For testing: force processing a given number of password rows.  If this quantity is
-- greater than the number of rows in Safari, the row processor will cycle through the
-- rows until forcedRowCount rows have been processed.  A value of 0 disables
-- forced processing.
property forcedRowCount : 0

-- Logging support
property logEnabled : true -- set to true to enable logging to a file
property logFilename : "get_safari12_passwords.log" as string
property logFile : ""

set logFile to ((path to desktop folder) as string) & logFilename as string

global logStartTimestamp
set logStartTimestamp to time of (current date)

if logEnabled is true then
	Debug("Log start: " & (time string of (current date)))
	display dialog "Logging enabled.  Log file is at: " & return & return & (POSIX path of logFile)
end if

-- Avoid a bug in Safari 13.x that prematurely closes the passwords dialog while active
if application "Safari" is running then
	set theResult to display dialog "Safari must be quit before this script can run.

Ok to quit Safari now?"
	if (button returned of theResult) is "Cancel" then
		error number -128
	end if
	tell application "Safari" to quit
	delay 1
end if

set csv_filepath to (path to desktop as text) & "pm_export.csv"

set invokedBy to ""
tell application "System Events"
	set invokedBy to get the name of the current application
	set theResult to display dialog "Safari will be launched, and its Passwords dialog opened.  Enter your password in that dialog to continue.

Allow the script to run to completion before disturbing your system. 
	
	Ok to launch Safari now?"
	if (button returned of theResult) is "Cancel" then
		error number -128
	end if
	
	activate "Safari"
end tell

set Entries to {}
set Entries to FetchEntries()

set theResult to write_csv_file(Entries, csv_filepath)
if not theResult then
	display dialog "There was an error writing the CSV data!"
	error number -128
end if

tell application "System Events" to tell application process "Safari"
	keystroke "w" using {command down}
end tell

tell application "Finder"
	reveal file csv_filepath
	activate
	--make new Finder window
	--set target of Finder window 1 to path to desktop
	--reveal csv_filepath
end tell

with timeout of 300 seconds
	tell application "System Events" to tell application process invokedBy
		set frontmost to true
		set dialogText to "All done!

There is now a file on your Desktop named:

    pm_export.csv

You may now convert it to a 1PIF file using the converter suite's \"csv\" converter.  The resulting 1PIF file may be imported into 1Password."
		try
			display dialog dialogText buttons {"Ok"} default button "Ok"
		end try
	end tell
end timeout

-- handlers

on UnlockPasswords()
	my Debug(" Opening Safari passwords dialog")
	tell application "System Events" to tell application process "Safari"
		set frontmost to true
		keystroke "," using {command down}
		set tb to toolbar 1 of window 1
		set buttonName to (name of button 4 of tb as string)
		click button 4 of tb
		
		set isLocked to true
		repeat while isLocked is true
			set uiElements to UI elements of (group 1 of group 1 of window 1)
			set nElements to the count of uiElements
			if nElements is 3 then
				set isLocked to true
				my Debug("   passwords are *locked* - waiting...")
				delay 1
			else
				set isLocked to false
				my Debug("   passwords are now unlocked")
				
			end if
		end repeat
	end tell
end UnlockPasswords

on FetchEntries()
	Debug("Entering FetchEntries()")
	
	tell application "Safari"
		activate
	end tell
	UnlockPasswords()
	
	set tableEntries to {}
	with timeout of extractionTimeout seconds
		try
			tell application "System Events" to tell application process "Safari"
				set frontmost to true
				local prefsWin
				
				set nRows to 0
				set nRowsPrev to -1
				set attempt to 1
				my Debug(" Sampling password data...")
				repeat while attempt ≤ maxAttempts
					set prefsWin to window 1
					set theTable to table 1 of scroll area 1 of group 1 of group 1 of prefsWin
					set nRows to the count of rows of table 1 of scroll area 1 of group 1 of group 1 of prefsWin
					if nRows is 0 then
						-- nothing found, try again
						my Debug("   attempt " & attempt & ": row count: 0")
					else if nRows is not nRowsPrev then
						my Debug("   attempt " & attempt & ": current row count: " & nRows & ", previous row count: " & nRowsPrev)
						set nRowsPrev to nRows
					else
						my Debug("   attempt " & attempt & ":  two consecutive attempts found " & nRows & " rows")
						exit repeat
					end if
					set attempt to attempt + 1
					delay 1
				end repeat
				
				-- bail: nothing found after maxAttemptss
				if nRows is 0 then
					my Debug("  No rows found in password table")
					display dialog "The password table appears to be empty" buttons {"Quit"} default button "Quit"
					error number -128
				end if
				
				-- bail: could not get consistent row data after two consecutive attempts
				if nRows is not nRowsPrev then
					set msg to "Failed to get identical password row data after " & maxAttempts & " tries"
					my Debug("    " & msg)
					display dialog msg buttons {"Quit"} default button "Quit"
					error number -128
				end if
				
				local rowIndex, currentRow, failedRows
				set currentRow to 1
				set failedRows to 0
				
				my Debug(" Processing " & nRows & " rows from the passwords dialog")
				if (forcedRowCount is not 0) then
					set nRowsToProcess to forcedRowCount
					my Debug("   Forced processing of " & forcedRowCount & " rows")
				else
					set nRowsToProcess to nRows
				end if
				
				repeat while currentRow ≤ nRowsToProcess
					if (forcedRowCount is not 0) then
						set rowIndex to 1 + ((currentRow - 1) mod nRows)
						my Debug("    ROW: " & currentRow & " (index used: " & rowIndex & ")")
					else
						set rowIndex to currentRow
						my Debug("    ROW: " & rowIndex)
					end if
					
					local myRow, row_open_attempts
					local theSite, theName, theUser, thePass, theURLs, urlList, rowValues, theSheet
					set {theTitle, theSite, theUser, thePass, theURLs} to {"Untitled", "", "", "", ""}
					set urlList to {}
					set theSheet to 0
					set row_open_attempts to 2
					
					-- Sheet entries w/out a title will not open with the first keypress of Return, but a 2nd attempt will
					repeat while row_open_attempts > 0
						tell theTable
							set myRow to row rowIndex
							select row rowIndex
							--delay 1
							set focused to true
							-- open the sheet
							keystroke return
							set focused to true
						end tell
						
						try
							set theSheet to sheet 1 of prefsWin
							set row_open_attempts to 0
							if theSheet is not 0 then
								-- Any of the URL, Username or Password values be empty					
								set theURLtable to table 1 of scroll area 1 of theSheet
								set nURLs to the count of rows of theURLtable
								my Debug("     URL count: " & nURLs)
								set url_index to 1
								repeat while url_index ≤ nURLs
									local aURL
									set aURL to (the value of static text of item 1 of UI element 1 of row url_index of theURLtable) as text
									if url_index is equal to 1 then
										if not (aURL is missing value or aURL is equal to "") then
											-- For the Title, just duplicate the URL field
											copy aURL to theSite
											copy aURL to theTitle
										end if
									else
										-- push extra URLs to the notes area
										set the end of urlList to aURL
									end if
									
									if aURL is missing value or aURL is equal to "" then
										my Debug("        URL " & url_index & ": " & "<site missing or empty>")
									else
										
										my Debug("        URL " & url_index & ": " & aURL)
									end if
									
									set url_index to url_index + 1
								end repeat
								
								try
									set theUser to value of attribute "AXValue" of text field 1 of theSheet
									my Debug("        Username: " & theUser)
								end try
								try
									set thePass to value of attribute "AXValue" of text field 2 of theSheet
								end try
								
								--if (count of urlList) is greater than 0 then
								--	set beginning of urlList to "Extra URLs"
								--end if
								
								set theURLs to Join(character id 59, urlList) of me
								local tmpList
								set tmpList to {theTitle, theSite, theUser, thePass, theURLs}
								copy tmpList to rowValues
								set the end of tableEntries to rowValues
								
								-- close the sheet
								keystroke return
							end if
							
						on error
							my Debug("      Sheet failed to open - Skipping Entry")
							set failedRows to failedRows + 1
							set row_open_attempts to row_open_attempts - 1
						end try
					end repeat
					set currentRow to currentRow + 1
				end repeat
			end tell
			
		on error errMsg number errNum
			if (errNum is -1712) then
				display dialog "Script time out while extracting Safari passwords
		" & errMsg
			else if errNum is -10006 then
				display dialog "Safari was quit - aborting"
			else
				display dialog "Error" & errNum & "
" & errMsg
			end if
			error number -128
		end try
	end timeout
	
	Debug("Leaving FetchEntries(): entries found: " & (count of tableEntries))
	
	return tableEntries
end FetchEntries

on write_csv_file(Entries, fpath)
	local rowdata
	
	Debug("Entering write_csv_file()")
	
	set beginning of Entries to {"Title", "Login URL", "Login Username", "Login Password", "Additional URLs"}
	
	set csvstr to ""
	set i to 1
	repeat while i ≤ (count of Entries)
		--say "Row " & i
		set rowdata to item i of Entries
		
		if csvstr is not "" then
			set csvstr to csvstr & character id 10
		end if
		
		set j to 1
		repeat while j ≤ (count of rowdata)
			--say "Column " & j
			set encoded to CSVCellEncode(item j of rowdata)
			if csvstr is "" then
				set csvstr to encoded
			else if j is 1 then
				set csvstr to csvstr & encoded
			else
				set csvstr to csvstr & "," & encoded
			end if
			set j to j + 1
		end repeat
		set i to i + 1
	end repeat
	
	Debug("  Writing CSV string to file: length: " & length of csvstr)
	set theResult to WriteTo(fpath, csvstr, «class utf8», false)
	Debug("  Done")
	Debug("Leaving write_csv_file()")
	
	return theResult
end write_csv_file

on WriteTo(targetFile, theData, dataType, append)
	try
		set targetFile to targetFile as text
		set openFile to open for access file targetFile with write permission
		if append is false then set eof of openFile to 0
		write theData to openFile starting at eof as dataType
		close access openFile
		return true
	on error
		try
			close access file targetFile
		end try
		return false
	end try
end WriteTo

on Debug(str)
	if logEnabled is not true then
		return
	end if
	set secs to ((time of (current date)) - logStartTimestamp) as string
	set secsPadded to text -4 thru -1 of ("0000" & secs)
	set msg to ((secsPadded & ": " & str & linefeed) as string)
	WriteTo(logFile, msg, «class utf8», true)
end Debug

on CSVCellEncode(cellstr)
	--say cellstr
	if cellstr is "" then return ""
	set orig to cellstr
	set cellstr to ""
	repeat with c in the characters of orig
		set c to c as text
		if c is "\"" then
			set cellstr to cellstr & "\"\""
		else
			set cellstr to cellstr & c
		end if
	end repeat
	
	if (cellstr contains "," or cellstr contains " " or cellstr contains "\"" or cellstr contains return or cellstr contains character id 10) then set cellstr to quote & cellstr & quote
	
	return cellstr
end CSVCellEncode

on SpeakList(l, name)
	say "List named " & name
	repeat with theItem in l
		say theItem
	end repeat
end SpeakList

on GetTitleFromURL(val)
	copy val to title
	-- applescript's lack of RE's sucks
	set pats to {"http://", "https://"}
	repeat with pat in pats
		set title to my ReplaceText(pat, "", title)
	end repeat
	return item 1 of my Split(title, "/")
end GetTitleFromURL

on ReplaceText(find, replace, subject)
	set prevTIDs to text item delimiters of AppleScript
	set text item delimiters of AppleScript to find
	set subject to text items of subject
	
	set text item delimiters of AppleScript to replace
	set subject to subject as text
	set text item delimiters of AppleScript to prevTIDs
	return subject
end ReplaceText

on Split(theString, theDelimiter)
	set oldDelimiters to AppleScript's text item delimiters
	set AppleScript's text item delimiters to theDelimiter
	set theArray to every text item of theString
	set AppleScript's text item delimiters to oldDelimiters
	return theArray
end Split

on Join(delims, l)
	local ret
	set prevTIDs to AppleScript's text item delimiters
	set AppleScript's text item delimiters to delims
	set ret to items of l as text
	set AppleScript's text item delimiters to prevTIDs
	return ret
end Join
