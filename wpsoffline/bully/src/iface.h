/*
    bully - retrieve WPA/WPA2 passphrase from a WPS-enabled AP

    Copyright (C) 2012  Brian Purcell <purcell.briand@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef	_IFACE_H
#define	_IFACE_H

char	BG_CHANS[] = "1,5,9,2,6,10,3,7,11,4,8";
char	AN_CHANS[] = "36,40,44,48,52,56,58,60";

struct cfreq {
	int	chan;
	int	freq;
} freqs[] = {
	{   1, 241200000 },
	{   2, 241700000 },
	{   3, 242200000 },
	{   4, 242700000 },
	{   5, 243200000 },
	{   6, 243700000 },
	{   7, 244200000 },
	{   8, 244700000 },
	{   9, 245200000 },
	{  10, 245700000 },
	{  11, 246200000 },
	{  12, 246700000 },
	{  13, 247200000 },
	{  14, 248400000 },
	{  34, 517000000 },
	{  36, 518000000 },
	{  38, 519000000 },
	{  40, 520000000 },
	{  42, 521000000 },
	{  44, 522000000 },
	{  46, 523000000 },
	{  48, 524000000 },
	{  52, 526000000 },
	{  56, 528000000 },
	{  58, 530000000 },
	{  60, 532000000 },
	{ 100, 550000000 },
	{ 104, 552000000 },
	{ 108, 554000000 },
	{ 112, 556000000 },
	{ 116, 558000000 },
	{ 120, 560000000 },
	{ 124, 562000000 },
	{ 128, 564000000 },
	{ 132, 566000000 },
	{ 136, 568000000 },
	{ 140, 570000000 },
	{ 149, 574500000 },
	{ 153, 576500000 },
	{ 157, 578500000 },
	{ 161, 580500000 },
	{ 165, 582500000 }
#define MAX_CHAN 165
};
#define	NUM_CHAN (sizeof(freqs)/sizeof(struct cfreq))


#endif /* _IFACE_H */
