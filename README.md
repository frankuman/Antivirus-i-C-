# Antivirus-i-C-
BTH, 2022, OB

Summary and conclusion of project
The purpose of the analysis was to make a risk assessment for an antivirus software and present these risks and consequences for comparison. 
How critical do we judge them to be, and what risk should be prioritized? 
In the risk analysis there were 10 different risks found where 3 were high priority, 5 were medium priority and 2 were low priority.
In the discussion it is written how these risks are a vulnerability to the software, and in the conclusion it is written how they should be handled and also how expensive it would be. 



The best way to handle the high priority risks, buffer overflow and traversal directory attack is to patch the software. For buffer overflow, there is a method called input validation. The method contains exceptions which are thrown whenever an overflow happens. 
Since some files could be read with a traversal directory attack, it has to be handled. It could be handled in various ways, but making the software from exceptions when there’s a directory that shouldn’t be touched is probably the easiest way. Hard-coding it this way and possibly making it so root-users could add some directories that should not be touched. This would make it harder to succeed in this attack. [7][8]
Implementing this into the software would possibly take 40-80 hours of work, depending on how fail-proof it should be.
A ransomware attack is on a different level than the before said risks. Ransomware attacks are so common now, both in huge enterprises such as WannaCry and even sometimes in private computers. To counter ransomware, you would need to add these to the database, and always run the antivirus on the downloaded content before you do anything else. If the ransomware is not sophisticated enough, the antivirus should be able to detect it. This would not take a lot of time to implement, but it is very important to do so. [9] 
Implementing something like this would not take too much time. The most time would be searching for the signatures that would suffice for security against ransomware attacks. Approximately 8 to 24 hours of work. There is a possibility to have the antivirus on a continuous scan, and when it detects a sort of malicious software it pauses it from being executed, and alarming the user that it found something. Implementing something like this would take around 24 more hours of work.
These risks mentioned should definitely be handled first, and after them the medium priority risks could be thought of. User Experience is something that can be improved with time, seeing and watching what users like, and don’t like. Both system crash and permission & privilege problems need more testing to fix.
Arbitrary code execution gets its probability minimized when the other risks get fixed. A more stable software does not have as many ways to get fiddled with. A serious reverse engineer could possibly still find a way to use the software in a malicious way, and more testing would be needed. This would be handled along the way while the software is being used, but around 4 hours of work per week, while it’s being used.
The approximate price for solving these security issues is 11000 Swedish crowns. There are always more security issues that could come up in the future and therefore the price could be much more.


	
