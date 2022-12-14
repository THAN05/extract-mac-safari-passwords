-- Exports Safari's saved passwords to a CSV file formatted for use with the converter suite's csv converter
--
-- Version 1.2
-- mike (at) cappella (dot) us
--
-- The script requires Safari version 11 or older
property maxSafariVersion : 11
set safariVersion to item 1 of Split(version of application "Safari", ".")

if safariVersion ≥ maxSafariVersion then
	display dialog "This script only supports Safari version " & maxSafariVersion & " or older." & return & return & "Use the Get_Safari_Passwords AppleScript instead." buttons {"Ok"} default button "Ok"
	error number -128
end if

-- Languages such as Japanese require the script to be saved as UTF-16.
-- Including this symbol persuades Script Editor's Export to ensure this.
property forceUTF16encoding : "🍎"

set export_fname to "pm_export"

set Entries to {}
set Entries to FetchEntries()
set beginning of Entries to {"Title", "Login URL", "Login Username", "Login Password"}

set csvstr to ""
set i to 1
repeat while i ≤ (count of Entries)
	--say "Row " & i
	set rowdata to item i of Entries
	
	if csvstr is not "" then
		set csvstr to csvstr & "
"
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

set theResult to WriteTo((path to desktop as text) & export_fname & ".csv", csvstr, «class utf8», false)
if not theResult then display dialog "There was an error writing the data!"

tell application "System Events" to tell application process "Safari"
	keystroke "w" using {command down}
end tell

tell application "System Events" to tell application process "Script Editor"
	set frontmost to true
	
	display dialog "All done!

There is now a file on your Desktop named:

pm_export.csv

You can convert it to a 1PIF for import into 1Password using the csv converter in the converter suite."
end tell


on FetchEntries()
	set tableEntries to {}
	delay 0.5
	tell application "System Events" to tell application process "Safari"
		set frontmost to true
		
		tell table 1 of scroll area 1 of group 1 of group 1 of window 1
			set nRows to the count of rows
			--say "Dialog has " & nRows & "rows."
			set i to 1
			repeat while i ≤ nRows
				-- say "Row " & i
				select row i
				--delay 1
				select text field 1 of row i
				set j to 1
				set rowValues to {}
				repeat while j ≤ (count of columns)
					set focused of text field j of row i to 1 -- to show full URI (vs the UI's sanitized version)
					set val to value of text field j of row i
					-- say "Value " & val
					-- For the Title, duplicate the URL field and strip the protocol
					if j is 1 then
						set end of rowValues to my GetTitleFromURL(val)
						--say last item of rowValues
					end if
					set end of rowValues to val
					set j to j + 1
				end repeat
				set the end of tableEntries to rowValues
				set i to i + 1
				--delay 1
			end repeat
		end tell
	end tell
	
	return tableEntries
end FetchEntries

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

on CSVCellEncode(cellstr)
	--say cellstr
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
	
	if (cellstr contains "," or cellstr contains " " or cellstr contains "\"") then set cellstr to quote & cellstr & quote
	
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

