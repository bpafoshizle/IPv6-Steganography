#!/usr/bin/perl
#
# Author: Barret Miller
# License: GPLv2
# 
# Description:
# 
# This script is part of my Honors Thesis topic of steganography
# in IPv6 source addresses. This program will accept a message in 
# ASCII format from a file if one is specified, and otherwise, it 
# will prompt the user to type in a message.
#
# 04/10/08
#
# Version:  .9

use strict;
#use warnings;

# Use the procedural interface to the Net::IP module
use Net::IP qw(:PROC);
use Switch;

# Message variables
my $message;
my $savedMessage;
my $pureMessage;
my $formatedHexString;
my $rawHexString;
my @byteArray;

# Global variables needed in the decodeFromMac function
my $prevMsg = "";
my $totalMsg = "";

# Address & interface arrays
my @oldLinkLocals;
my @oldSiteLocals;
my @oldGlobals;
my @macList;
my @ifaceIdList;

# Always only one localhost so we don't need a count or an array
my $oldLocalHost = "";

# Number of the differently scoped addresses
my $oldSiteLocalCount = 0;
my $oldLinkLocalCount = 0;
my $oldGlobalCount = 0;

##################################################################
# Begin Config Variables										 #
##################################################################

# Input File Name
my $inFileName;

# Interval in seconds to send messages out on
# If left 0, then the default prefered 
# lifetime of IPv6 temporary addresses is used
my $interval = 0;

# link layer interface to use
my $interface;

# Specifies whether to use the faster transmit method with
# a more complicated decode, or the slower transmit method
# with a clean decode.
my $txFast = 0;

# User may specify a connect script to 
# connect to the internet
my $connectScript;

# User may specify to encode message into
# the Mac address in which case it will go out
# over IPv4 as well
my $macEncode = 0;

# Spcifies mode to use: either msg or inject. 
# If msg the behavior is to embed a message into the
# source address field of packets in one of two main
# ways - either though manipulation of the mac address
# or through direct insertion into the interface ID portion
# of the source address field of a packet. If injection
# mode is used, no message is inserted and the user may 
# set the source address field (among others) to whatever
# value desired. 
my $mode = "msg";

# Specifies the value for the source address field (only used 
# in injection mode)
my $srcAddr = '::1';

# Specifies the destination address field's value 
# (only used in direct msg mode or in injection mode)
my $dstAddr = '::1';

# Specifies the source port value for a frame (only
# used in direct msg mode, or in injection mode)
my $srcPort;

# Specifies the destination port value for a frame
# (only used in direct message mode, or in injection
# mode)
my $dstPort = '6666';

# Specifies the transport layer protocol to use
# only either UPD or TCP currently.
my $transport = 'tcp';

# Specifies the destination MAC address to use
# If none is specified, then a random one is
# generated. LSB of first octet cannot be 1. 
# Used only in direct message mode or in
# injection mode.
my $dstMAC;

# Specifies the source MAC address to use
# If none is specified, then the MAC from
# the specified interface is used.
# Used only in direct message mode or in injection mode.
my $srcMAC;

# Specifies the scope of the prefix for the Source IPv6 address to 
# be used
my $scope = 'link';

# Specifies TCP options to use as a 
# hex string
my $tcpOpts;

# Specifies a file containing the application 
# layer data to pack into the layer
# seven object of the packet. 
my $dataFile;

# Signals that the user wishes to use encryption
# on the message before encoding it into the specified
# medium of MAC address or interface id. Default is to 
# not encrypt
my $encrypt = 0;

# The keyFile to retrieve the key and initialization 
# vector for encryption and decryption
my $keyFile;

# Filter string used by the dump object (sniffer) to
# selectively grab packets from the network
my $filterString = "";

# Mode to capture ('offline' or 'live')
my $capture = 'live';

# Capture file to use if capture mode
# is 'offline'
my $pcap = 'live.pcap';

# Flag to signal if mac decoding will be needed
my $macDecode = 0;

# If set, the program will go on capturing
# packets indefinitely in decode mode
my $continuousDump = 0;

# Specifies verbose debug mode
my $debug = 0;

##################################################################
# End Config Variables										     #
##################################################################

handleConf();
handleArgs(@ARGV);

if($mode eq 'msg')
{
	# Read message from a file
	if($inFileName)
	{
		# Sanity checking
		check4Iface();
		check4Interval();

		open(IN, $inFileName) || die("Can't open file $inFileName");

		# Read the message from the file
		while(<IN>)
		{
			$message .= $_;
		}
		chomp($message);
		close(IN);

		# Save message before metadata and encryption
		$pureMessage = $message;

		# If macEncoding is used, there is a different method of 
		# signifying the end of the message, than if directEncoding
		# is used. 
		if($macEncode == 1)
		{
			$message = $message . "<eNd>";
			$savedMessage = $message;
			if($encrypt == 1)
			{
				$message = encryptMessage($message);
			}

			# Now run in the background and change mac address on interval
			sendMessageMac();
		}
		else
		{
			# Append the bytelength to the front of the message enclosed in
			# '<>' brackets. Perl implicitly casts integer value returned from
			# the getByteLength() function to a string
			my $byteLength = getByteLength($message);
			#print("Bytes in message: $byteLength\n");
			$message = "<" . $byteLength . ">" . $message;
			$savedMessage = $message;
			if($encrypt == 1)
			{		
				$message = encryptMessage($message);
			}
			
			sendMessageDirect();
		}
	
		cleanUpLogs();
	}
	# Read message from STDIN if no file argument is given
	else
	{
		check4Iface();
		check4Interval();
	
		print("Enter your message. When finished, enter a \"^D\"".
			" without the quotes .\n/>");
	
		my @userEnteredLines;
		@userEnteredLines = <STDIN>;
		$message = join("", @userEnteredLines); 
		chomp($message);

		# Save message before metadata addition and encryption.
		# Used for debugging.
		$pureMessage = $message;
	
		if($macEncode == 1)
		{
			$message = $message . "<eNd>";
			$savedMessage = $message;
			if($encrypt)
			{
				$message = encryptMessage($message);
			}
			sendMessageMac();
		}
		else
		{

			my $byteLength = getByteLength($message);
			$message = "<" . $byteLength . ">" . $message;
			$savedMessage = $message;
			if($encrypt)
			{	
				$message = encryptMessage($message);
			}
			sendMessageDirect();
		}
	
		cleanUpLogs();
	}
}
# Injection mode
elsif($mode eq 'inject')
{
	# Ad hoc packet sending mode
}
# Mode for testing formatting of message and environment
elsif($mode eq 'testFormat')
{
	# Read message from a file
	if($inFileName)
	{
		# Sanity checking
		check4Iface();
		check4Interval();

		open(IN, $inFileName) || die("Can't open file $inFileName");

		# Read the message from the file
		while(<IN>)
		{
			$message .= $_;
		}
		chomp($message);
		close(IN);	

		# Append the bytelength to the front of the message enclosed in
		# '<>' brackets. Perl implicitly casts integer value returned from
		# the getByteLength() function to a string
		my $byteLength = getByteLength($message);
		#print("Bytes in message: $byteLength\n");
		$message = "<" . $byteLength . ">" . $message;
	}
	else
	{
		warn("No message file specified.\n");
	}

	testFormating();
}
elsif($mode eq 'decode')
{
	use Net::Packet::Env qw($Env);
	use Net::Packet::Consts qw(:ipv6 :eth :dump);
	require Net::Packet::Frame;
	require Net::Packet::DescL3;
	require Net::Packet::Dump;
	require Net::Packet::IPv4;
	require Net::Packet::IPv6;
	require Net::Packet::UDP;
	require Net::Packet::TCP;
	require Net::Packet::ETH;

	if($debug)
	{
		printReceiverInfo();
	}
	
	# Set the interface to send frames on
	$Env->dev($interface);

	my $msgReceived = 0;
	my $dumpMode;
	my $decodedMsg = "";
	my $noStore = 0;
	my $cipher;

	# Create crypt object for decryption if necessary
	if($encrypt)
	{
		open(IN, $keyFile) or die "Could not open keyfile $keyFile for decryption";
		my $contents = <IN>;
		$contents .= <IN>;
		close(IN);

		$contents =~ /key: (\w*)\niv: (\w*)/;
		my $key = pack("H*", $1);
		my $iv = pack("H*", $2);

		$cipher = Crypt::CBC->new(
			-literal_key => 1,
			-header => 'none',
			-key => $key,
			-iv => $iv,
			-cipher => 'Blowfish',
			-padding => 'space',
		);
	}
	
	if($capture eq 'offline')
	{
		$dumpMode = NP_DUMP_MODE_OFFLINE;
	}
	elsif($capture eq 'live')
	{
		$dumpMode = NP_DUMP_MODE_ONLINE;
		$noStore = 1;
	}
	else
	{
		die "Couldn't understand capture mode: $capture\n";
	}

	# Instantiate dump object
    my $dump = Net::Packet::Dump->new(
   		mode          => $dumpMode,
   		file          => $pcap,
   		filter        => $filterString,
   		promisc       => 1,
        snaplen       => 1514,
        noStore       => $noStore,
        keepTimestamp => 1,
        unlinkOnClean => 1,
        overwrite     => 1,
    );

	$dump->start;

	# Get packets from saved file
	if($capture eq 'offline')
	{
		# Start cipher to be passed down the chain for 
		# decryption if necessary
		if($encrypt)
		{
			$cipher->start('d');
		}
		
		# Loop until all frames in the file are used
		while(my $frame = $dump->next)
		{
			my $ip = $frame->l3;	
			my $sa = $ip->src;
			$decodedMsg .= decodeMessage($sa, $cipher);
		}

		# If a cipher was set up for decryption, close it
		if($encrypt)
		{
			$cipher->finish();
		}
		
		# Print out the message to a file named based on 
		# the pcap file that the message came from
		my $msgFileName = 'msgFrom-' . $pcap;
		open(OUT, ">$msgFileName");
		print(OUT $decodedMsg);
		close(OUT);
	}
	# Get packets from wire
	elsif($capture eq 'live')
	{
		# Capture indefinitely
		if($continuousDump)
		{
			# Constantly look for messages on the wire
			while(1)
			{
				# Start cipher to be passed down the chain for 
				# decryption if necessary
				if($encrypt)
				{
					$cipher->start('d');
				}
				
				# Set the flag to signal when the length of the message 
				# has been determined
				my $lengthDetermined = 0;
				my $byteTotal;

				# Loop until the total message has been received
    			while(!$msgReceived)
				{
					if(my $frame = $dump->next)
					{
						my $ip = $frame->l3;
						my $sa = $ip->src;
						$decodedMsg .= decodeMessage($sa, $cipher);
						
						if($macDecode == 1)
						{
							# If the string <eNd> followed by zero or more
							# whitespace characters at the end of the string 
							if($decodedMsg =~ /<eNd>/)
							{
								$msgReceived = 1;
							}
						}
						else
						{
							# Grab the total byte count of the message if it 
							# hasn't already been grabbed. It might not be grabbed
							# in the case that the string representation of the number
							# of total bytes in the message is greater than 8 bytes 
							# and therefore takes up more than one interface ID which
							# is only 64 bits. 
							if(!$lengthDetermined && $decodedMsg =~ /^<(\d+)>/)
							{
								$lengthDetermined = 1;
								$byteTotal = $1;
	
								# Remove the length tag from the string
								# This is done in here so it will only have to
								# do substitution (and check the whole string possibly)
								# once. This has the added benefit that 
								# lengthDetermined is set so in the off chance that
								# a message originally began with a number surrounded by
								# '<>' brackets, it will not remove it from the message.
								$decodedMsg =~ s/^<\d+>//;
							}

							# If the total message has been received, set the flag
							if($decodedMsg && $byteTotal && getByteLength($decodedMsg) >= $byteTotal)
							{
								$msgReceived = 1;

								# Remove possible white space from the end of the message
								$decodedMsg = trimEnd($decodedMsg);
							}
						}
					}
				}
				
				# Reset msgRecieved
				$msgReceived = 0;

				# If a cipher was set up for decryption, close it
				if($encrypt)
				{
					$cipher->finish();
				}
	
				# Print out the message to a file named based on 
				# the current timestamp
				my $msgFileName = 'msg-' . makeTimestamp();
				open(OUT, ">$msgFileName");
				print(OUT $decodedMsg);
				close(OUT);

				# Clear $decodedMsg
				$decodedMsg = "";

				#dump->stop();
				#dump->clean();
			}
		}
		else
		{
			# Start cipher to be passed down the chain for 
			# decryption if necessary
			if($encrypt)
			{
				$cipher->start('d');
			}
			
			# Set the flag to signal when the length of the message 
			# has been determined to 0
			my $lengthDetermined = 0;
			my $byteTotal;
			
			# Loop until the total message has been received
			while(!$msgReceived)
			{
				if(my $frame = $dump->next)
				{
					my $ip = $frame->l3;
					my $sa = $ip->src;
					$decodedMsg .= decodeMessage($sa, $cipher);	
					if($macDecode == 1)
					{
						if($decodedMsg =~ /<eNd>/)
						{
							$msgReceived = 1;
						}
					}
					else
					{
						# Grab the total byte count of the message if it 
						# hasn't already been grabed. It might not be grabbed
						# in the case that the string representation of the number
						# of total bytes in the message is greater than 8 bytes 
						# and therefore takes up more than one interface ID which
						# is only 64 bits. 
						if(!$lengthDetermined && $decodedMsg =~ /^<(\d+)>/)
						{
							$lengthDetermined = 1;
							$byteTotal = $1;
	
							# Remove the length tag from the string
							# This is done in here so it will only have to
							# do substitution (and check the whole string possibly)
							# once. This has the added benefit that 
							# lengthDetermined is set so in the off chance that
							# a message originally began with a number surrounded by
							# '<>' brackets, it will not remove it from the message.
							$decodedMsg =~ s/^<\d+>//;
						}
	
						# If the total message has been received, set the flag
						if($decodedMsg && $byteTotal && getByteLength($decodedMsg) >= $byteTotal)
						{
							$msgReceived = 1;
							
							# Remove possible whitespace from end of message
							$decodedMsg = trimEnd($decodedMsg);
						}
					}
				}
			}
			
			# If a cipher was set up for decryption, close it
			if($encrypt)
			{
				$cipher->finish();
			}
	
			# Print out the message to a file named based on 
			# the current timestamp
			my $msgFileName = 'msg-' . makeTimestamp();
			open(OUT, ">$msgFileName");
			print(OUT $decodedMsg);
			close(OUT);
			$dump->stop();
			$dump->clean();
		}
	}
	else
	{
		die "Couldn't understand capture mode: $capture\n";
	}
}
else
{
	die "Mode not understood. Specify 'msg', 'inject', 'testFormat', or 'decode' via command line or config file\n";
}

##########################################################
#		Subroutines										 #
##########################################################
sub printFormatedHexString
{
	my $message = $_[0];
	print(toFormatedHexString($message) . "\n");
}

sub printRawHexString
{
	my $message = $_[0];
	print(toHexRawString($message) . "\n");
}

# Function to clean up all relevant log files on the 
# system to cover our tracks. 
sub cleanUpLogs
{
	# Clean up all relevant log files on the system
}

# Function to trim the whitespace off the end of
# a string
sub trimEnd
{
	my ($string) = @_;
	$string =~ s/\s+$//;
	return $string;
}

# Subroutine that takes a string argument and returns 
# the length in bytes of that string, in case the 
# actual encoding is more than one byte.
sub getByteLength
{
	my ($string) = @_;
	my $hexString = unpack('H*', $string);
	my $numBytes = length($hexString)/2;
	return $numBytes;
}

# Function to make sure an interface is specified and to 
# try to get one from the /proc/net/if_inet6 otherwise
sub check4Iface
{
	# If no interface is specified in the conf file or
	# as an argument, then pull one from the output 
	# of 'cat /proc/net/if_inet6'
	if(!$interface)
	{
		# Need Error check
		my $ifcgOutput = `cat /proc/net/if_inet6`;
		
		# Look for something like eth0
		$ifcgOutput =~ /(eth[0-9]).*/;
		$interface = $1;

		# Look for something like wlan0
		# if not eth# was found.
		if(!$interface)
		{
			$ifcgOutput =~ /(wlan[0-9]).*/;
			$interface = $1;
		}

		# If there is still no interface found, then print error message and quit
		if(!$interface)
		{
			die "No link layer interface found. You can specify one with the -if argument\n" . 
				"or in the /etc/m2a.conf file with the interface=iface option";
		}
	}
}

# Function to make sure an interval is specified, 
# and, if not, to 
sub check4Interval
{
	# If no time interval was given in the conf file or
	# as an argument, then use the tmp_prefered_lifetime 
	# value currently set for temporary IPv6 addresses
	# in /proc/sys/net/ipv6/conf/[interface]/temp_prefered_lft
	if(!$interval)
	{
		open(IN, "/proc/sys/net/ipv6/conf/$interface/temp_prefered_lft") or die "Cannot open temp_prefered_lft file";
		$interval = <IN>;
		close(IN);
	}
}

# Function to check for and handle the 
# config file
sub handleConf
{	
	if(-e "/etc/m2a.conf")
	{
		open(IN, "/etc/m2a.conf");

		my $line;
		while(<IN>)
		{
			$line = $_;
			if($line !~ /^#/)
			{
				$line =~ /(.*)=(.*)/;
				my $var = $1;
				my $val = $2;
				seedVars($var, $val);
			}
		}
		close(IN);
	}
}

# Function to be used along with the handleConf function
# to initialize program variables from the config file
sub seedVars
{
	my ($var, $val) = @_;

	switch($var)
	{
		case "interval"
		{
			$interval = $val;
		}
		case "msgfile"
		{
			$inFileName = $val;
		}
		case "interface"
		{
			$interface = $val;
		}
		case "txfast"
		{
			$txFast = $val;
		}
		case "cnctscript"
		{
			$connectScript = $val;
		}
		case "macencode"
		{
			$macEncode = $val;
		}
		case "dstPort"
		{
			$dstPort = $val;
		}
		case "srcPort"
		{
			$srcPort = $val;
		}
		case "dstAddr"
		{
			$dstAddr = $val;
		}
		case "srcAddr"
		{
			$srcAddr = $val;
		}
		case "mode"
		{
			$mode = $val;
		}
		case "transport"
		{
			$transport = $val;
		}
		case "srcMAC"
		{
			$srcMAC = $val;
		}
		case "dstMAC"
		{
			$dstMAC = $val;
		}
		case "scope"
		{
			$scope = $val;
		}
		case "tcpOpts"
		{
			$tcpOpts = $val;
		}
		case "dataFile"
		{
			$dataFile = $val;
		}
		case "encrypt"
		{
			$encrypt = $val;
		}
		case "keyFile"
		{
			$keyFile = $val;
		}
		case "filterString"
		{
			$filterString = $val;
		}
		case "capture"
		{
			$capture = $val;
		}
		case "pcap"
		{
			$pcap = $val;
		}
		case "macdecode"
		{
			$macDecode = $val;
		}
		case "continuousDump"
		{
			$continuousDump = $val;
		}
		case "dbug"
		{
			$debug = $val;
		}
		# Add more functionality later
	}
}

# Function to handle arguments passed to the 
# program
sub handleArgs()
{
	my @args = @_;
	my $argLength = @args;
	
	for(my $i = 0; $i < $argLength; $i++)
	{
		my $arg = $args[$i];

		switch($arg)
		{
			# Interval in seconds
			case "-i" 
			{
				$interval =  $args[$i + 1]; 
				$i++;
			}
			# Input message file
			case "-f"
			{
				$inFileName = $args[$i + 1];
				$i++;
			}
			# Link layer interface to use
			case "-if"
			{
				$interface = $args[$i + 1];
				$i++;
			}
			case "-clean"
			{
				$txFast = 0;
			}
			case "-cs"
			{
				$connectScript = $args[$i + 1];
				$i++;
			}
			# Encode the message to mac address where it can be sent
			# over IPv4 or IPv6. 
			case "-mac"
			{
				$macEncode = 1;
			}
			# Send message mode or inject packet mode
			case "-m"
			{
				$mode = $args[$i + 1];
				$i++;
			}
			# The source address to use (only used in inject
			# packet mode)
			case "-s"
			{
				$srcAddr = $args[$i + 1];
				$i++;
			}
			# Destination address to use (only used in inject 
			# packet mode or in direct message mode -- not used
			# in mac encode mode).
			case "-d"
			{
				$dstAddr = $args[$i + 1];
				$i++;
			}
			# Source port to use (only used in inject packet
			# mode or in direct message mode -- not used in mac
			# encode mode).  
			case "-sp"
			{
				$srcPort = $args[$i + 1];
				$i++;
			}
			# Destination port to use (only used in inject packet
			# mode or in direct message mode -- not used in mac
			# encode mode)
			case "-dp"
			{
				$dstPort = $args[$i + 1];
				$i++;
			}
			# Transport layer protocol to use. Currently only 
			# supports UDP and TCP
			case "-t"
			{
				$transport = $args[$i + 1];
				$i++;
			}
			# The source MAC address to use. Only applicable to 
			# injection mode and direct message mode.
			case "-sm"
			{
				$srcMAC = $args[$i + 1];
				$i++;
			}
			# The destination MAC address to use. Only applicaple to 
			# injection mode and direct message mode.
			case "-dm"
			{
				$dstMAC = $args[$i + 1];
				$i++;
			}
			# The scope of the prefix to use. i.e. link, site, global,
			# or local 
			case "-scope"
			{
				$scope = $args[$i + 1];
				$i++;
			}
			case "-tcpOpts"
			{
				$tcpOpts = $args[$i + 1];
				$i++;
			}
			case "-dataFile"
			{
				$dataFile = $args[$i + 1];
				$i++;
			}
			case "-e"
			{
				$encrypt = 1;
			}
			case "-k"
			{
				$keyFile = $args[$i + 1];
				$i++;
			}
			case "-fs"
			{
				$filterString = $args[$i + 1];
				$i++;
			}
			case "-c"
			{
				$capture = $args[$i + 1];
				$i++;
			}
			case "-pc"
			{
				$pcap = $args[$i + 1];
				$i++;
			}
			case "-md"
			{
				$macDecode = 1;
			}
			case "-cd"
			{
				$continuousDump = 1;
			}
			case "-dbug"
			{
				$debug = 1;
			}
			else
			{
				printUsage();
			}
			# Add more functionality later
		}
	}
}

# Function to print the usage of the command line arguments
sub printUsage
{
	print("Usage: \"m2a.pl [-i <interval in seconds>] [-f <message file>]\n" . 
		  "[-if <interface>] [-clean] [-cs <connectScript>] [-mac] [-m <mode>]\n" .
		  "[-s <sourceAddr>] [-d <destAddr>] [-sp <srcPort>] [-dp <dstPort>]\n" .
		  "[-t <transport layer>] [-sm <srcMAC>] [-dm <dstMAC>] [-scope <prefix scope>]\n".
		  "[-dbug]\"\n"); 
}

# Function to send the message out using the Net::Packet 
# module to inject packets with arbitrary source address
# fields into the network directly without having to 
# modify the MAC address of an interface which involves 
# downtime for the host
sub sendMessageDirect
{
	use Net::Packet::Env qw($Env);
	use Net::Packet::Consts qw(:ipv6 :eth);
	require Net::Packet::Frame;
	require Net::Packet::DescL3;
	require Net::Packet::Dump;
	require Net::Packet::IPv4;
	require Net::Packet::IPv6;
	require Net::Packet::UDP;
	require Net::Packet::TCP;
	require Net::Packet::ETH;
	
	# Set the interface to send frames on
	$Env->dev($interface);
	$Env->noFrameAutoDump(1);

	# Call setup method to set up the environment
	setup();

	if($debug)
	{
		printSenderInfo();
	}
	
	my $eth;
	my $ip;
	my $l4;
	my $l7;
	my $frame;
	my $prefix;
	my $srcAddr;
	my $num2Send = @ifaceIdList;
	my $sendTime = time;

	if($debug)
	{
		print("Total Ifaces to send: $num2Send\n");
	}

	while($num2Send > 0)
	{
		my $msg2Send = shift(@ifaceIdList);
		$num2Send = @ifaceIdList;

		my $env = Net::Packet::Env->new(dev => $interface);

		# Get the prefix to use for the source address. 
		$prefix = getPrefix(extractOldAddress($scope, $interface));
		$srcAddr = $prefix . ":" . $msg2Send;
	
		# If no destination MAC address is given, then generate 
		# a random valid MAC
		if(!$dstMAC)
		{
			$dstMAC = generateMAC();
			$dstMAC =~ s/\w\w(:\w\w:\w\w:\w\w:\w\w:\w\w)/\1/;
			$dstMAC = generateCleanOctet() . $dstMAC;
		}
		# If no source MAC is given, then use the MAC from the
		# specified interface.
		if(!$srcMAC)
		{
			$srcMAC = $env->mac;
		}
	
		# Create link layer object
		$eth = Net::Packet::ETH->new(
			type => NP_ETH_TYPE_IPv6,
			dst => $dstMAC,
			src => $srcMAC,
		);
	
		# Create network layer IPv6 object
		# using next header value based on 
		# whether TCP or UDP will be used
		if($transport eq 'udp')
		{
			$ip = Net::Packet::IPv6->new(
				src => $srcAddr,
				dst => $dstAddr,
				nextHeader => NP_IPv6_PROTOCOL_UDP,
			);
		}
		# Default is TCP so no need to explicitly
		# set it when creating object, but will
		# anyway as per good coding practice
		else
		{
			$ip = Net::Packet::IPv6->new(
				src => $srcAddr,
				dst => $dstAddr,
				nextHeader => NP_IPv6_PROTOCOL_TCP,
			);
		}
	
		# Create a transport layer object
		if($transport eq 'udp')
		{
			# If the user has specified a src port use it 
			if($srcPort)
			{
				$l4 = Net::Packet::UDP->new(
					dst => $dstPort,
					src => $srcPort,
				);
			}
			# Otherwise use whitchever port the OS
			# gives
			else
			{
				$l4 = Net::Packet::UDP->new(
					dst => $dstPort,
				);
			}
		}
		else
		{
			# If the user has specified a src port use it 
			if($srcPort)
			{
				$l4 = Net::Packet::TCP->new(
					dst => $dstPort,
					src => $srcPort,
				);
			}
			# Otherwise use whichever port the OS
			# gives
			else
			{
				$l4 = Net::Packet::TCP->new(
					dst => $dstPort,
				);
			}
		}

		# If there is a data file, use it.
		if($dataFile)
		{			
			open(IN, $dataFile) || die "Cannot open $dataFile data file\n";
			my $data = <IN>;
			close($data);
			$l7 = Net::Packet::Layer7->new(
				data => $data,
			);
		}
	
		# Pack everything into a Frame object
		# for sending using a layer 7 object if
		# there is one
		if($l7)
		{
			$frame = Net::Packet::Frame->new(
				l2 => $eth,
				l3 => $ip,
				l4 => $l4,
				l7 => $l7,
			);
		}
		else
		{
			$frame = Net::Packet::Frame->new(
				l2 => $eth,
				l3 => $ip,
				l4 => $l4,
			);
		}
	
		# Spinlock that will spin until the time is right to
		# send the frame based on the interval
		while(time < $sendTime){}
		
		if($debug)
		{
			print("Sending: $msg2Send\n");
		}
		
		$frame->send;

		# Reset the next time to send out a frame
		$sendTime = time + $interval;
	}
}

# Function to send the message out on a given interval
# by encoding it into a series of Mac addresses.
sub sendMessageMac
{
	# Call setup method to set up the environment
	setup();

	if($debug)
	{
		printSenderInfo();
	}
	my $numMacs = @macList;
	my $msg2Send = shift(@macList);

	# Dummy var delete later
	my $scriptOut;

	if($debug)
	{
		print("Total MACs to send: $numMacs\n");
		print("Changing mac to $msg2Send.\n");
	}
	changeMac($msg2Send);
	
	if(defined $connectScript)
	{
		# Need Error check
		$scriptOut = `$connectScript`;
		#print($scriptOut);
	}
	
	# Number of messages left to send
	my $num2Send = @macList;
	
	# Calculate the next time to change the mac address
	# using the current time and the interval 
	my $oldTime = (time + $interval);

	# Make system calls to change mac address. Internet is 
	# temporarily unavailable
	while($num2Send > 0)
	{
		if(time > $oldTime)
		{
			$msg2Send = shift(@macList);
			if($debug)
			{
				print("Changing mac to $msg2Send.\n");
			}
			changeMac($msg2Send);
			
			if(defined $connectScript)
			{
				# Need Error check
				$scriptOut = `$connectScript`;
				#print($scriptOut);
			}

			# Update the next time to send
			$oldTime = (time + $interval);

			# Update the number of messages left
			$num2Send = @macList;
		}
	}

}

# Function to decode a message from a source address
sub decodeMessage
{
	my ($sa, $cipher) = @_;
	my $ipObj = new Net::IP ($sa) or die Net::IP::Error();
	
	my $expandedIP = $ipObj->ip();
	my $ifaceId = getIfaceId($expandedIP);
	my $message = "";
	# Get rid of colons
	$ifaceId =~ s/://g;
	if($macDecode)
	{
		$message = decodeFromMac($ifaceId, $cipher);
	}
	else
	{
		$message = decodeStraight($ifaceId, $cipher);
	}
	return $message;
}

# Function to decode the message if it was sent using the macEncode method
sub decodeFromMac
{
	my ($msg, $cipher) = @_;

	# Short MAC encoding was used. Only need to extract 
	# the lower 5 bytes
	if($txFast != 1)
	{
		# If message is same as the one just received, then 
		# return the empty string because we have already
		# received this piece. 
		if($msg eq $prevMsg)
		{
			return "";
		}
		else
		{
			$prevMsg = $msg;
		}

		if($debug)
		{
			print("Interface ID: $msg\n");
		}
		# Cut out the FFFE from the middle, and chop off the first
		# byte that isn't part of the message. 
		$msg =~ s/.{2}(.{4})[Ff]{2}[Ff]{1}[Ee]{1}(.{6})/$1$2/;
		
		if($debug)
		{
			print("Extracted message info in hex: $msg\n");
		}
		
		# Turn the hex representation back into ascii chars
		$msg = pack('H*', $msg);

		if($encrypt)
		{
			if($totalMsg ne "")
			{
				$msg = $totalMsg . $msg;
			}
			
			my $msgLength = getByteLength($msg);
			
			if($msgLength >= 8)
			{
				# Remove the first 8 chars and save leftover
				$totalMsg = substr($msg, 8);

				if($debug)
				{
					print("Ciphertext after pack: $msg\n");
				}

				# Decrypt first 8 chars
				$msg = decryptMessage(substr($msg,0,8), $cipher);	

				if($debug)
				{
					print("Plaintext after decrypt: $msg\n");
				}

				return $msg;
			}
			else
			{
				$totalMsg = $msg;
				$msg = "";
				return $msg;
			}
		}
		else
		{
			if($debug)
			{
				print("Message after pack: $msg\n");
			}
			return $msg;
		}
	}
	# Long MAC encoding was used. Need to generate a 
	# tree of possible decodings
	else
	{
	}
}

# Function to decode the message if it was sent using the normal method
# of encoding straight to an iface ID
sub decodeStraight
{
	my ($msg, $cipher) = @_;

	if($debug)
	{
		print("Message from Iface ID: $msg\n");
	}

	$msg = pack('H*', $msg);

	if($encrypt)
	{
		if($debug)
		{
			print("Ciphertext after pack: $msg\n");
		}

		$msg = decryptMessage($msg, $cipher);
		
		if($debug)
		{
			print("Plaintext after decrypt: $msg\n");
		}

		return $msg;
	}
	else
	{
		if($debug)
		{
			print("Message after pack: $msg\n");
		}

		return $msg;
	}
}

# System calls to change the current mac address for
# an interface
sub changeMac
{
	my ($newMac) = @_;
	# Need Error check
	my $cmdOutput = `ifconfig $interface down`;
 	# Need Error check
	$cmdOutput = `ifconfig $interface hw ether $newMac`;
	# Need Error check
	$cmdOutput = `ifconfig $interface up`;
}

# Function that runs all the necessary functions to set 
# up the environment. Must run this before anything
# useful can really be done.
sub setup
{
	toRawHexString($message);
	toFormatedHexString($message);
	toByteArray($message);
	getOldAddresses();
	
	if($macEncode ==  1)
	{

		if($txFast == 1)
		{
			# Encodes to all 6 octets
			# Cleanup must be done
			encode2MAC();
		}
		else 
		{
			# Encodes to lower 5 octets
			# Takes longer to get msg out
			encode2MACshort();
		}
	}
	else
	{
		encode2IfaceId();
	}
}

# This function 
sub cleanupMacs
{
	# If the user wants the fast transmit
	# Then the LSB of the first octet cannot
	# be set to 1 because that signifies 
	# multicast, and it is not allowed on an
	# interface
	foreach my $mac (@macList)
	{
		my $nibble = substr($mac, 1, 1);
		switch($nibble)
		{
			case '1'
			{
				# Replace the 1 with a 0
				substr($mac, 1, 1, '0');
			}
			case '3'
			{
				# Replace the 3 with a 2
				substr($mac, 1, 1, '2');
			}
			case '5'
			{
				# Replace the 5 with a 4
				substr($mac, 1, 1, '4');
			}
			case '7'
			{
				# Replace the 7 with a 6
				substr($mac, 1, 1, '6');
			}
			case '9'
			{
				# Replace the 9 with an 8
				substr($mac, 1, 1, '8');
			}
			case 'B'
			{
				# Replace the B with an A
				substr($mac, 1, 1, 'A');
			}
			case 'D'
			{
				# Replace the D with a C
				substr($mac, 1, 1, 'C');
			}
			case 'F'
			{
				# Replace the F with an E
				substr($mac, 1, 1, 'E');
			}
		}
	}
}

# Function to encode the contents of the byte array into 
# a series of mac addresses. 
sub encode2MAC
{
	my @byteArrayCopy = @byteArray;
	my $byteCount = @byteArray;
	my $numMacs = int($byteCount / 6);
	my $leftOverBytes = $byteCount % 6;
	
	for(my $i = 0; $i < $numMacs; $i++)
	{
		my $mac = "";

		for(my $j = 0; $j < 6; $j++)
		{
			$mac = $mac . shift(@byteArrayCopy);
		}
		$mac =~ s/(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)/\1:\2:\3:\4:\5:\6/;

		$macList[$i] = $mac;
	}

	if($leftOverBytes != 0)
	{
		# Generate a random MAC address
		my $tempMac = generateMAC();

		switch($leftOverBytes)
		{
			case 1
			{
				$tempMac =~ s/\w\w(:\w\w:\w\w:\w\w:\w\w:\w\w)/\1/;
				$tempMac = shift(@byteArrayCopy) . $tempMac;
			}
			case 2
			{
				$tempMac =~ s/\w\w:\w\w(:\w\w:\w\w:\w\w:\w\w)/\1/;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = pop(@byteArrayCopy) . $tempMac;
			}
			case 3
			{
				$tempMac =~ s/\w\w:\w\w:\w\w(:\w\w:\w\w:\w\w)/\1/;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = pop(@byteArrayCopy) . $tempMac;
			}
			case 4
			{
				$tempMac =~ s/\w\w:\w\w:\w\w:\w\w(:\w\w:\w\w)/\1/;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = pop(@byteArrayCopy) . $tempMac;
			}
			case 5
			{
				$tempMac =~ s/\w\w:\w\w:\w\w:\w\w:\w\w(:\w\w)/\1/;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = pop(@byteArrayCopy) . $tempMac;
			}
		}

		$macList[$numMacs] = $tempMac;
	}

	# Make sure the LSB of the first octet is not 1
	cleanupMacs();
}

# Function to encode the contents of the byte array into 
# the lower 5 octets of a series of mac addresses. 
sub encode2MACshort
{
	my @byteArrayCopy = @byteArray;
	my $byteCount = @byteArray;
	my $numMacs = int($byteCount / 5);
	my $leftOverBytes = $byteCount % 5;
	
	for(my $i = 0; $i < $numMacs; $i++)
	{
		my $mac = "";

		for(my $j = 0; $j < 5; $j++)
		{
			$mac = $mac . shift(@byteArrayCopy);
		}
		$mac =~ s/(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)/\1:\2:\3:\4:\5/;
		$mac = generateCleanOctet() . ":" . $mac;

		$macList[$i] = $mac;
	}

	if($leftOverBytes != 0)
	{
		# Generate a random MAC address
		my $tempMac = generateMAC();

		switch($leftOverBytes)
		{
			case 1
			{
				$tempMac =~ s/\w\w:\w\w(:\w\w:\w\w:\w\w:\w\w)/\1/;
				$tempMac = generateCleanOctet() . ":" . shift(@byteArrayCopy) . $tempMac;
			}
			case 2
			{
				$tempMac =~ s/\w\w:\w\w:\w\w(:\w\w:\w\w:\w\w)/\1/;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = generateCleanOctet() . ":" . pop(@byteArrayCopy) . $tempMac;
			}
			case 3
			{
				$tempMac =~ s/\w\w:\w\w:\w\w:\w\w(:\w\w:\w\w)/\1/;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = generateCleanOctet() . ":" . pop(@byteArrayCopy) . $tempMac;
			}
			case 4
			{
				$tempMac =~ s/\w\w:\w\w:\w\w:\w\w:\w\w(:\w\w)/\1/;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = ":" . pop(@byteArrayCopy) . $tempMac;
				$tempMac = generateCleanOctet() . ":" . pop(@byteArrayCopy) . $tempMac;
			}
		}

		$macList[$numMacs] = $tempMac;
	}
}

# Method to encode the message bytes into 
# ipv6 interface ID's
sub encode2IfaceId
{
	#use array @ifaceIdList
	my @byteArrayCopy = @byteArray;
	my $byteCount = @byteArray;
	my $numIfaceIds = int($byteCount / 8);
	my $leftOverBytes = $byteCount % 8;

	for(my $i = 0; $i < $numIfaceIds; $i++)
	{
		my $ifaceId = "";

		for(my $j = 0; $j < 8; $j++)
		{
			$ifaceId = $ifaceId . shift(@byteArrayCopy);
		}
		$ifaceId =~ s/(\w\w\w\w)(\w\w\w\w)(\w\w\w\w)(\w\w\w\w)/\1:\2:\3:\4/;

		$ifaceIdList[$i] = $ifaceId;
	}

	if($leftOverBytes != 0)
	{
		# Generate a random interface ID
		my $tempIfaceId = generateIfaceId();

		switch($leftOverBytes)
		{
			case 1
			{
				$tempIfaceId =~ s/\w\w(\w\w:\w\w\w\w:\w\w\w\w:\w\w\w\w)/\1/;
				$tempIfaceId = shift(@byteArrayCopy) . $tempIfaceId;
			}
			case 2
			{
				$tempIfaceId =~ s/\w\w\w\w(:\w\w\w\w:\w\w\w\w:\w\w\w\w)/\1/;
				$tempIfaceId =  shift(@byteArrayCopy) . shift(@byteArrayCopy) . $tempIfaceId;
			}
			case 3
			{
				$tempIfaceId =~ s/\w\w\w\w:\w\w(\w\w:\w\w\w\w:\w\w\w\w)/\1/;
				$tempIfaceId = shift(@byteArrayCopy) . shift(@byteArrayCopy) . ":" 
							   . shift(@byteArrayCopy) . $tempIfaceId;
			}
			case 4
			{
				$tempIfaceId =~ s/\w\w\w\w:\w\w\w\w(:\w\w\w\w:\w\w\w\w)/\1/;
				$tempIfaceId = shift(@byteArrayCopy) . shift(@byteArrayCopy) . ":" 
								. shift(@byteArrayCopy) . shift(@byteArrayCopy) . $tempIfaceId;
			}
			case 5
			{
				$tempIfaceId =~ s/\w\w\w\w:\w\w\w\w:\w\w(\w\w:\w\w\w\w)/\1/;
				$tempIfaceId = shift(@byteArrayCopy) . shift(@byteArrayCopy)  . ":"
								. shift(@byteArrayCopy) . shift(@byteArrayCopy) . ":"
								. shift(@byteArrayCopy) . $tempIfaceId;
			}
			case 6
			{
				$tempIfaceId =~ s/\w\w\w\w:\w\w\w\w:\w\w\w\w(:\w\w\w\w)/\1/;
				$tempIfaceId = shift(@byteArrayCopy) . shift(@byteArrayCopy) . ":"
								. shift(@byteArrayCopy) . shift(@byteArrayCopy) . ":"
								. shift(@byteArrayCopy) . shift(@byteArrayCopy) . $tempIfaceId;
			}
			case 7
			{
				$tempIfaceId =~ s/\w\w\w\w:\w\w\w\w:\w\w\w\w:\w\w(\w\w)/\1/;
				$tempIfaceId = shift(@byteArrayCopy) . shift(@byteArrayCopy) . ":"
								. shift(@byteArrayCopy) . shift(@byteArrayCopy) . ":"
								. shift(@byteArrayCopy) . shift(@byteArrayCopy) . ":"
								. shift(@byteArrayCopy) . $tempIfaceId;
			}
		}

		$ifaceIdList[$numIfaceIds] = $tempIfaceId;
	}
}

# Function to get the prefix from an address
# Assumes a 64 bit prefix length for all global addresses, if 
# you need to get the prefix of a global address with a prefix 
# length other than 64 bits, use getPrefixGlobal(address, prefixLength)
sub getPrefix
{
	my ($address) = @_;

	# Insert the colons for Net::IP to recognize the address
	$address =~ s/(.{4})(.{4})(.{4})(.{4})(.{4})(.{4})(.{4})(.{4})/\1:\2:\3:\4:\5:\6:\7:\8/;

	#Turn $address into a Net::IP object
	$address = new Net::IP ($address) or die Net::IP::Error() . "\nInvalid address: [$address]\n"; 
	
	my $retVal = "";
	$retVal = $address->ip();

	$retVal =~ s/(.{19}).*/\1/;

	return $retVal;
}

# Function to get the interface id portion of an address.
# Assumes 64 bit if id length
sub getIfaceId
{
	my ($address) = @_;
	$address =~ s/.*(.{19})/\1/;
	return $address;
}

# Function that takes two params: $scope, $interface
# and returns the address or the null string if it 
# doesn't have an address for those parameters.
# scope can be the following strings:
# 'global', 'site', 'link', or 'local'
sub extractOldAddress
{
	my ($scope, $interface) = @_;
	my $retVal = "";

	if($scope eq "global")
	{
		$retVal = extractOldGlobal($interface);
	}
	elsif($scope eq "site")
	{
		$retVal = extractOldSite($interface);
	}
	elsif($scope eq "link")
	{
		$retVal = extractOldLink($interface);
	}
	elsif($scope eq "local")
	{
		$retVal = $oldLocalHost;
	}

	return $retVal;
}

# Function to get the address associated with the 
# given interface from the global collection
sub extractOldGlobal
{
	my ($interface) = @_;
	my $retVal = "";

	foreach my $addressHash (@oldGlobals)
	{
		if($addressHash->{'iface'} eq $interface)
		{
			$retVal = $addressHash->{'addr'};
		}
	}

	return $retVal;
}

# Function to get the address associated with the 
# given interface from the site local collection
sub extractOldSite
{
	my ($interface) = @_;
	my $retVal = "";

	foreach my $addressHash (@oldSiteLocals)
	{
		if($addressHash->{'iface'} eq $interface)
		{
			$retVal = $addressHash->{'addr'};
		}
	}

	return $retVal;
}

# Function to get the address associated with the 
# given interface from the link local collection
sub extractOldLink
{
	my ($interface) = @_;
	my $retVal = "";

	foreach my $addressHash (@oldLinkLocals)
	{
		if($addressHash->{'iface'} eq $interface)
		{
			$retVal = $addressHash->{'addr'};
		}
	}

	return $retVal;
}

# Subroutine to get the starting addresses of the machine running this program
# from /proc/net/if_inet6 file
sub getOldAddresses
{
	my $globalCount = 0;
	my $siteLocalCount = 0;
	my $linkLocalCount = 0;
	
	open(IN, "/proc/net/if_inet6");
	my @ip6Addresses = <IN>;
	close(IN);

	foreach my $address (@ip6Addresses)
	{
		chomp($address);

		if($address =~ /(0{31}1).*lo$/)
		{
			$oldLocalHost = $1;
		}
		# Capture the link local hex address and the interface id
		elsif($address =~ /(^[Ff][Ee]80[a-fA-F0-9]{28})(\s|\d)*(\w*$)/)
		{
			$oldLinkLocals[$linkLocalCount] = { addr => $1, iface => $3};
			$linkLocalCount++;
		}
		# Capture the site local hex address and the interface id
		elsif($address =~ /(^[Ff][Cc]00[a-fA-F0-9]{28})(\s|\d)*(\w*$)/)
		{
			$oldSiteLocals[$siteLocalCount] = { addr => $1, iface => $3};
			$siteLocalCount++;
		}
		# The address must be a global; still uses regex to capture relevant parts
		elsif($address =~ /(^[a-fA-F0-9]{32})(\s|\d)*(\w*$)/)
		{
			$oldGlobals[$globalCount] = { addr => $1, iface => $3};
			$globalCount++;
		}
		else
		{
			die("Cant interpret address from /proc/net/if_inet6. Shuting down.");
		}
	}

	$oldLinkLocalCount = $linkLocalCount;
	$oldSiteLocalCount = $siteLocalCount;
	$oldGlobalCount = $globalCount;
}

# Function to convert an ascii message to a a string 
# that represents it's actual hexadecimal value
# abstracts the unpack function  built in to perl
sub toRawHexString
{
	$rawHexString = unpack("H*", $_[0]);
}

# Function to format the message string into bytes separated by colons
# e.g. a7b345 --> a7:b3:45
sub toFormatedHexString
{
	my $message = $_[0];
	my $rawHexString = toRawHexString($message);
	my $hexStringLength = length($rawHexString);
	my $byteIndex = 0;
	my $returnString = "";
	
	while($byteIndex < $hexStringLength)
	{
		$returnString = $returnString . substr($rawHexString, $byteIndex, 2);
		$byteIndex += 2;
	
		if($byteIndex < $hexStringLength)
		{
				$returnString = $returnString . ":";
		}
	}

	$formatedHexString = $returnString;
}

# Function to return an array of strings representing the bytes
# of the original message with one byte (two characters)
# per slot in the list
sub toByteArray
{
	my $message = $_[0];
	my $formatedHexString = toFormatedHexString($message);
	@byteArray = split(":", $formatedHexString);
}

sub generateMAC()
{
	my $mac = "";
	my @macDigits;

	#Generate 12 random integers between 0 and 15 inclusive
	for(my $i = 0; $i < 12; $i++)
	{
		$macDigits[$i] = int(rand(16));
	}

	
	foreach my $digit(@macDigits)
	{
		switch($digit)
		{
			case 10 {$mac = $mac . "a";}
			case 11 {$mac = $mac . "b";}
			case 12 {$mac = $mac . "c";}
			case 13 {$mac = $mac . "d";}
			case 14 {$mac = $mac . "e";}
			case 15 {$mac = $mac . "f";}
			else {$mac = $mac . $digit;}
		}
	}
	
	$mac =~ s/(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)/\1:\2:\3:\4:\5:\6/;
	return $mac;
}

# This function will return a 'clean' octet string
# in hex formet. An octet is considered clean if it
# can be used as the first octet in a MAC address,
# i.e. it isn't odd; i.e. the LSB is not a 1.  
sub generateCleanOctet()
{
	my $octet;
	my $digit;

	#Generate 2 random integers between 0 and 15 inclusive
	$octet = int(rand(16));
	$digit = int(rand(16));

	switch($octet)
	{
		case 10 {$octet = "a";}
		case 11 {$octet = "b";}
		case 12 {$octet = "c";}
		case 13 {$octet = "d";}
		case 14 {$octet = "e";}
		case 15 {$octet = "f";}
	}

	switch($digit)
	{
		case 1 {$octet = $octet . "0";}
		case 3 {$octet = $octet . "2";}
		case 5 {$octet = $octet . "4";}
		case 7 {$octet = $octet . "6";}
		case 9 {$octet = $octet . "8";}
		case 10 {$octet = $octet . "a";}
		case 11 {$octet = $octet . "a";}
		case 12 {$octet = $octet . "c";}
		case 13 {$octet = $octet . "c";}
		case 14 {$octet = $octet . "e";}
		case 15 {$octet = $octet . "e";}
		else {$octet = $octet . $digit;}
	}
	return $octet;
}

sub generateIfaceId
{
	my $ifaceId = "";
	my @ifaceIdDigits;

	#Generate 16 random integers between 0 and 15 inclusive
	for(my $i = 0; $i < 16; $i++)
	{
		$ifaceIdDigits[$i] = int(rand(16));
	}

	
	foreach my $digit(@ifaceIdDigits)
	{
		switch($digit)
		{
			case 10 {$ifaceId = $ifaceId . "a";}
			case 11 {$ifaceId = $ifaceId . "b";}
			case 12 {$ifaceId = $ifaceId . "c";}
			case 13 {$ifaceId = $ifaceId . "d";}
			case 14 {$ifaceId = $ifaceId . "e";}
			case 15 {$ifaceId = $ifaceId . "f";}
			else {$ifaceId = $ifaceId . $digit;}
		}
	}
	
	$ifaceId =~ s/(\w\w\w\w)(\w\w\w\w)(\w\w\w\w)(\w\w\w\w)/\1:\2:\3:\4/;
	return $ifaceId;
}

# Function to encrypt the message using blowfish encryption
# and the Crypt::CBC module. Used manual mode so the 
# encryption key and initialization vector must be provided in a file
# specified by keyFile variable. To generate a random key and iv, use
# genKey.pl which will create a file named "key" in the same 
# directory it is run in.  
sub encryptMessage
{
	my ($msg) = @_;

	use Crypt::CBC;

	open(IN, $keyFile) or die "Could not open keyfile $keyFile for encryption";
	my $contents = <IN>;
	$contents .= <IN>;
	close(IN);

	$contents =~ /key: (\w*)\niv: (\w*)/;
	my $key = pack("H*", $1);
	my $iv = pack("H*", $2);

	my $cipher = Crypt::CBC->new(
		-literal_key => 1,
		-header => 'none',
		-key => $key,
		-iv => $iv,
		-cipher => 'Blowfish',
		-padding => 'space',
	);

	# Must encrypt the message in 8 byte chunks 
	# in order for decryption to work because it 
	# will be received 8 bytes at a time
	my $cipherText = $cipher->encrypt($msg);
	return $cipherText;
}

# Function to decrypt the message using blowfish encryption
# and the Crypt::CBC module. Used manual mode so the 
# encryption key and initialization vector must be provided in a file
# specified by keyFile variable. To generate a random key and iv, use
# genKey.pl which will create a file named "key" in the same 
# directory it is run in.  
sub decryptMessage
{
	my ($cipherText, $cipher) = @_;
	my $msg = $cipher->crypt($cipherText);

	# For some reason the initial call to crypt always returns the 
	# empty string, so I must call twice on the first pass. 
	# It shouldn't hurt ????
	$msg = $cipher->crypt($cipherText);
	return $msg;
}

# Function to create and return a string timestamp
sub makeTimestamp
{
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
                                                localtime(time);
	my @months = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );
	my $month = $months[$mon];
	$year += 1900;

	return "$mday\_$month\_$year-$hour.$min.$sec";
}

#subroutine to test the other functionality of this module
sub testFormating
{
	toRawHexString($message);
	toFormatedHexString($message);
	toByteArray($message);


	print("Using interface $interface\n");
	print("Using interval $interval\n");

	print("Message:\n$message" . "\n" .
		"Raw Hex:\n$rawHexString" . "\n" .
		"Formated Hex:\n$formatedHexString" . "\n" .
		"Byte Array: \n");

	foreach my $slot (@byteArray)
	{
		print("$slot\n");
	}


	print("***********************************************************************\n");
	
	print("\nOld Address extraction testing\n");
	
	getOldAddresses();
	
	print("Localhost/loopback address: \n" . $oldLocalHost . "\n");
	print("Global addresses found: \n");
	foreach my $global (@oldGlobals)
	{
		print("Address: " . $global->{'addr'} . " if:" . $global->{'iface'} . "\n");
	}	
	print("old global count: " . $oldGlobalCount . "\n");
	
	print("Site local addresses found: \n");
	foreach my $siteLocal (@oldSiteLocals)
	{
		print("Address: " . $siteLocal->{'addr'} . " if:" . $siteLocal->{'iface'} . "\n");
	}	
	print("Old site local count: " . $oldSiteLocalCount . "\n");
	print("Link local addresses found: \n");
	foreach my $linkLocal (@oldLinkLocals)
	{
		print("Address: " . $linkLocal->{'addr'} . " if:" . $linkLocal->{'iface'} . "\n");
	}
	print("Old link local count: " . $oldLinkLocalCount . "\n");


	print("calling extractOldAddress('local', 'lo'):\n");
	print(extractOldAddress("local", "lo") . "\n");
	print("calling extractOldAddress('link', 'eth0'):\n");
	print(extractOldAddress("link", "eth0") . "\n");
	print("calling extractOldAddress('site', 'eth0'):\n");
	print(extractOldAddress("site", "eth0") . "\n");
	print("calling extractOldAddress('global', 'eth0'):\n");
	print(extractOldAddress("global", "eth0") . "\n\n");

	print("calling extractOldAddress('link', 'wlan0'):\n");
	print(extractOldAddress("link", "wlan0") . "\n");
	print("calling extractOldAddress('site', 'wlan0'):\n");
	print(extractOldAddress("site", "wlan0") . "\n");
	print("calling extractOldAddress('global', 'wlan0'):\n");
	print(extractOldAddress("global", "wlan0") . "\n\n");	

	print("***********************************************************************\n");
	print("Calling getPrefix(extractOldAddress($scope, $interface)\n");
	print(getPrefix(extractOldAddress($scope, $interface)) . "\n");


	print("***********************************************************************\n");
	print("Calling encode2MAC()\n");
	encode2MAC();
	print("Printing MACs\n");
	foreach my $mac (@macList)
	{
		print($mac . "\n");
	}
	print("**********************************************************************\n");
	print("Calling encode2MACshort()\n");
	encode2MACshort();
	print("Printing MACs\n");
	foreach my $mac (@macList)
	{
		print($mac . "\n");
	}

	print("**********************************************************************\n");
	print("Calling encode2IfaceId()\n");
	encode2IfaceId();
	print("Printing ifaceIds\n");
	foreach my $ifaceId (@ifaceIdList)
	{
		print($ifaceId . "\n");
	}
}

# Debuging method to print relevent settings and information
# on the sender side.
sub printSenderInfo
{
	print("DEBUG MODE: PRINTING SENDER SETTINGS...\n");
	print("Mode: $mode\n");
	print("Interface: $interface\n");
	print("Interval: $interval\n");
	print("Mac Encode: $macEncode\n");
	if($macEncode)
	{
		print("Long Mac Encode: $txFast\n");
	}
	else
	{
		print("PACKET CRAFTING ATTRIBUTES:\n");
		print("Transport layer: $transport\n");
		if($transport eq 'tcp')
		{
			print("TCP options: $tcpOpts\n");
		}
		print("Prefix Scope: $scope\n");
		print("Destination address: $dstAddr\n");
		print("Destination MAC: $dstMAC\n");
		print("Destination Port: $dstPort\n");
		print("Source Port: $srcPort\n");
		print("Source MAC: $srcMAC\n");
		print("Data File: $dataFile\n");
	}
	print("Encryption: $encrypt\n");
	if($encrypt)
	{
		print("Keyfile: $keyFile\n");
	}

	if($inFileName)
	{
		print("Message from file: $inFileName\n");
	}
	else
	{
		print("Message from STDIN:\n");
	}
	print("Message:[$pureMessage]\n");
	print("Message with metadata:[$savedMessage]\n");
	print("Bytes with metadata: " . unpack('H*', $savedMessage) . "\n");
	
	if($encrypt)
	{
		print("Bytes after encryption:\n$formatedHexString" . "\n");
	}
}

# Function to print the relevant settings and information on the 
# receiver side.
sub printReceiverInfo
{
	print("DEBUG MODE: PRINTING RECEIVER SETTINGS...\n");
	print("Mode: $mode\n");
	print("Interface: $interface\n");
	print("Mac Decode: $macDecode\n");
	if($macDecode)
	{
		print("Long Mac Encode: $txFast\n");
	}
	print("Encryption: $encrypt\n");
	if($encrypt)
	{
		print("Keyfile: $keyFile\n");
	}
	print("Sniffing Filter: $filterString\n");
	print("Capture mode: $capture\n");
	if($capture eq 'offline')
	{
		print("Pcap file: $pcap\n");
	}
	else
	{
		print("Sniff indefinitly: $continuousDump\n");
	}
}
