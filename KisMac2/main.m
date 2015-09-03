/*
<<<<<<< 651cabc6a59177b5257d540dbc8b5321710c46ca
 
 File:			PrefsClient.h
 Program:		KisMAC
 Author:		Geoffrey Kruse
 Changes:       Vitalii Parovishnyk(1012-2015)
 
 Description:	KisMAC is a wireless stumbler for MacOS X.
 
 This file is part of KisMAC.
 
 Most parts of this file are based on aircrack by Christophe Devine.
 
 KisMAC is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License, version 2,
 as published by the Free Software Foundation;
 
 KisMAC is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with KisMAC; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

int main(int argc, const char *argv[])
{
    @autoreleasepool
    {
        int retVal = NSApplicationMain(argc, argv);
=======
        File:			main.m
        Program:		KisMAC
		Author:			Geoffrey Kruse
		Description:	This file is part of KisMAC.

    KisMAC is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2,
    as published by the Free Software Foundation;

    KisMAC is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with KisMAC; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#import <Cocoa/Cocoa.h>

int main(int argc, char *argv[])
{
    @autoreleasepool
    {
        int retVal = NSApplicationMain(argc,  (const char **) argv);
>>>>>>> Merge branch 'master' of https://github.com/0x90/wifi-arsenal
        return retVal;
    }
}
