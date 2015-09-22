
#Function to put multiple plots on one page
multiplot <- function(..., plotlist=NULL, cols) {
  require(grid)
  
  # Make a list from the ... arguments and plotlist
  plots <- c(list(...), plotlist)
  
  numPlots = length(plots)
  
  # Make the panel
  plotCols = cols                          # Number of columns of plots
  plotRows = ceiling(numPlots/plotCols) # Number of rows needed, calculated from # of cols
  
  # Set up the page
  grid.newpage()
  pushViewport(viewport(layout = grid.layout(plotRows, plotCols)))
  vplayout <- function(x, y)
    viewport(layout.pos.row = x, layout.pos.col = y)
  
  # Make each plot, in the correct location
  for (i in 1:numPlots) {
    curRow = ceiling(i/plotCols)
    curCol = (i-1) %% plotCols + 1
    print(plots[[i]], vp = vplayout(curRow, curCol ))
  }
  
}


## Summarizes data.
## Gives count, mean, standard deviation, standard error of the mean, and confidence interval (default 95%).
##   data: a data frame.
##   measurevar: the name of a column that contains the variable to be summariezed
##   groupvars: a vector containing names of columns that contain grouping variables
##   na.rm: a boolean that indicates whether to ignore NA's
##   conf.interval: the percent range of the confidence interval (default is 95%)
summarySE <- function(data=NULL, measurevar, groupvars=NULL, na.rm=FALSE,
                      conf.interval=.95, .drop=TRUE) {
  require(plyr)
  
  # New version of length which can handle NA's: if na.rm==T, don't count them
  length2 <- function (x, na.rm=FALSE) {
    if (na.rm) sum(!is.na(x))
    else       length(x)
  }
  
  # This is does the summary; it's not easy to understand...
  datac <- ddply(data, groupvars, .drop=.drop,
                 .fun= function(xx, col, na.rm) {
                   c( N    = length2(xx[,col], na.rm=na.rm),
                      mean = mean   (xx[,col], na.rm=na.rm),
                      sd   = sd     (xx[,col], na.rm=na.rm)
                   )
                 },
                 measurevar,
                 na.rm
  )
  
  # Rename the "mean" column    
  datac <- rename(datac, c("mean"=measurevar))
  
  datac$se <- datac$sd / sqrt(datac$N)  # Calculate standard error of the mean
  
  # Confidence interval multiplier for standard error
  # Calculate t-statistic for confidence interval: 
  # e.g., if conf.interval is .95, use .975 (above/below), and use df=N-1
  ciMult <- qt(conf.interval/2 + .5, datac$N-1)
  datac$ci <- datac$se * ciMult
  
  return(datac)
}


#notwendige Bibliotheken laden
require(ggplot2)

#Arbeitspfad setzen für Experiment
experiment_szenario <- "MINSTREL-BLUES-Messungen/2-links-Minstrel-Blues-@Bennis-home-11.07.2012"
setwd(paste("/Volumes/cracker/data/nfs/thomas/experiments/",experiment_szenario,"/data/datamining",sep=""))

mac_mon1_20 = read.csv(file="proto=tcp-packetsize=1420-weight=40-channel=1-mon1.csv", header=TRUE)
mac_mon0_20 = read.csv(file="proto=tcp-packetsize=1420-weight=40-channel=1-mon1.csv", header=TRUE)


#plotting sender ofdm_weak_detection=on
ggplot( data = mac_mon1_20, aes (x=round_any(rx_counter_diff / mac_counter_diff * 100,10,floor))) +
  geom_area(aes(y = ..ndensity..), stat = "bin")

  geom_area(aes(y=rx_counter_diff / mac_counter_diff * 100, group = round_any(timestamp, 10, floor)), stat = "bin")
  #geom_point( aes (y=mac_counter_diff / 40000, colour = "mac_clock"), size = 1, alpha=I(0.2)) +
  #geom_boxplot(aes(y=rx_counter_diff / mac_counter_diff * 100, group = round_any(timestamp, 10, floor)), outlier.colour = "red", outlier.size = 1, alpha=0.3)
	geom_smooth( aes (x=timestamp - timestamp[1], y=rx_counter_diff / mac_counter_diff * 100, colour = "rx_busy"), size = 1, alpha=0.8) +
	geom_smooth( aes (x=timestamp - timestamp[1], y=ed_counter_diff / mac_counter_diff * 100, colour = "energy_busy"), size = 1, alpha=I(0.5)) +
	geom_area( aes (x=timestamp - timestamp[1], y=tx_counter_diff / mac_counter_diff * 100, colour = "tx_busy"), size = 1, alpha=I(0.5)) +
		  ylim(0,170000) + 
#		  xlim (400,410) +
#		  scale_y_log10() +
		  scale_colour_manual("MAC states", c("mac_clock"="black", "rx_busy"="green", "energy_busy"="blue", "tx_busy"="red")) +
		  ylab("register count [ticks]") + xlab("time [sec]") + opts(title='rx MAC states at TEL (ofdm-weak=on)')
states_af

states_eb <- ggplot( data = data$eb$part_0$register ) +
	          geom_point( aes (x=timestamp - timestamp[1], y=mac_counter_diff, colour = "mac_clock"), size = 1, alpha=I(0.05)) +
#		  geom_point( aes (x=timestamp - timestamp[1], y=(rx_counter_diff), colour = "rx_busy"), size = 1, alpha=I(0.8)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=(ed_counter_diff), colour = "energy_busy"), size = 1, alpha=I(0.01)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=(tx_counter_diff), colour = "tx_busy"), size = 1, alpha=I(0.5)) +
#		  geom_point( data=data$tel$ofdmweak_on$mon0_payload, aes(x=V1 - V1[1], y=50000), size = 5, alpha=I(1), shape=2) +
		  ylim(0,200000) + 
#		  xlim (400,410) +
#		  scale_y_log10() +
		  scale_colour_manual("MAC states", c("mac_clock"="black", "rx_busy"="green", "energy_busy"="blue", "tx_busy"="red")) +
		  ylab("register count [ticks]") + xlab("time [sec]") + opts(title='rx MAC states at EB (ofdm-weak=on)')
states_eb

states_eb <- ggplot( data = data$eb$ofdmweak_on$register ) +
	          geom_point( aes (x=timestamp - timestamp[1], y=mac_counter_diff, colour = "mac_clock"), size = 1, alpha=I(0.2)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=(rx_counter_diff), colour = "rx_busy"), size = 3, alpha=I(0.8)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=(ed_counter_diff), colour = "energy_busy"), size = 2, alpha=I(0.5)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=(tx_counter_diff), colour = "tx_busy"), size = 2, alpha=I(0.5)) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(6, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(9, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(12, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(18, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(24, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(36, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(48, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(54, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_point( data=data$eb$ofdmweak_on$mon0_payload, aes(x=V1 - V1[1], y=50000), size = 5, alpha=I(1), shape=2) +
		  ylim(0,170000) + 
#		  xlim (400,410) +
#		  scale_y_log10() +
		  scale_colour_manual("MAC states", c("mac_clock"="black", "rx_busy"="green", "energy_busy"="blue", "tx_busy"="red")) +
		  ylab("register count [ticks]") + xlab("time [sec]") + opts(title='rx MAC states at EB (ofdm-weak=on)')

states_vws <- ggplot( data = data$vws$ofdmweak_on$register ) +
	          geom_point( aes (x=timestamp - timestamp[1], y=mac_counter_diff, colour = "mac_clock"), size = 1, alpha=I(0.2)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=RM_double_sample(rx_counter_diff), colour = "rx_busy"), size = 3, alpha=I(0.8)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=RM_double_sample(ed_counter_diff), colour = "energy_busy"), size = 2, alpha=I(0.5)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=RM_double_sample(tx_counter_diff), colour = "tx_busy"), size = 2, alpha=I(0.5)) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(6, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(9, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(12, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(18, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(24, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(36, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(48, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(54, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_point( data=data$vws$ofdmweak_on$mon0_payload, aes(x=V1 - V1[1], y=5000), size = 5, alpha=I(1), shape=20) +
		  ylim(0,170000) + 
#		  xlim (400,410) +
#		  scale_y_log10() +
		  scale_colour_manual("MAC states", c("mac_clock"="black", "rx_busy"="green", "energy_busy"="blue", "tx_busy"="red")) +
		  ylab("register count [ticks]") + xlab("time [sec]") + opts(title='MAC states at rx TEL (ofdm-weak=on)')
states_vws

states_bib <- ggplot( data = data$bib$ofdmweak_on$register ) +
	          geom_point( aes (x=timestamp - timestamp[1], y=mac_counter_diff, colour = "mac_clock"), size = 1, alpha=I(0.2)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=(rx_counter_diff), colour = "rx_busy"), size = 3, alpha=I(0.8)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=(ed_counter_diff), colour = "energy_busy"), size = 2, alpha=I(0.5)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=(tx_counter_diff), colour = "tx_busy"), size = 2, alpha=I(0.5)) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(6, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(9, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(12, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(18, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(24, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(36, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(48, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(54, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_point( data=data$bib$ofdmweak_on$mon0_payload, aes(x=V1 - V1[1], y=50000), size = 5, alpha=I(1), shape=2) +
		  ylim(0,170000) + 
#		  xlim (400,410) +
#		  scale_y_log10() +
		  scale_colour_manual("MAC states", c("mac_clock"="black", "rx_busy"="green", "energy_busy"="blue", "tx_busy"="red")) +
		  ylab("register count [ticks]") + xlab("time [sec]") + opts(title='rx MAC states at BIB (ofdm-weak=on)')


states_ma <- ggplot( data = data$ma$ofdmweak_on$register ) +
	          geom_point( aes (x=timestamp - timestamp[1], y=mac_counter_diff, colour = "mac_clock"), size = 1, alpha=I(0.2)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=(rx_counter_diff), colour = "rx_busy"), size = 3, alpha=I(0.8)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=(ed_counter_diff), colour = "energy_busy"), size = 2, alpha=I(0.5)) +
		  geom_point( aes (x=timestamp - timestamp[1], y=(tx_counter_diff), colour = "tx_busy"), size = 2, alpha=I(0.5)) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(6, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(9, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(12, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(18, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(24, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(36, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(48, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  geom_hline( yintercept=CALC_tx_busy_ticks(54, 128), colour = "grey10", size = 0.5, linetype = 3) +
		  ylim(0,170000) + 
#		  xlim (400,410) +
#		  scale_y_log10() +
		  scale_colour_manual("MAC states", c("mac_clock"="black", "rx_busy"="green", "energy_busy"="blue", "tx_busy"="red")) +
		  ylab("register count [ticks]") + xlab("time [sec]") + opts(title='txcont MAC states at MA')

PLOT_double_graph(states_ma, states_vws)



#broadcast-szenario auswählen und alle traces in liste "data" einlesen ...data$ma$ofdmweak_on$register, 
broadcaster <- "ma"
nodeliste <- c("eb")
#, "ma", "eb", "vws", "a", "tel", "sg", "hft", "tc", "c", "bib", "af", "en", "ew")
data <- list()

for (i in nodeliste) {
  #read traces where ofdm-weak-detection=on
  part1 <- list (
    register   		= read.csv(file=paste("ofdmweak-1/sender=",broadcaster,"/datamining/",i,"-register.csv",sep=""), header=TRUE),
    mon0			= read.csv(file=paste("ofdmweak-1/sender=",broadcaster,"/datamining/",i,"-mon0.csv",sep=""), header=TRUE, sep = ",", dec='.'),
    #    mon0_payload		= if (is.null(count.fields(file=paste("ofdmweak-1/sender=",broadcaster,"/datamining/",i,"-mon0.csv.payload",sep="")))){mon0_payload = 0}
    #      else { mon0_payload	= read.csv(file=paste("ofdmweak-1/sender=",broadcaster,"/datamining/",i,"-mon0.csv.payload",sep=""), header=FALSE, sep = " ", dec='.')},
    mon0_broken_crc 		= read.csv(file=paste("ofdmweak-1/sender=",broadcaster,"/datamining/",i,"-mon0.csv.broken_crc",sep=""), header=TRUE),
    #    mon0_broken_crc_payload 	= read.csv(file=paste("ofdmweak-1/sender=",broadcaster,"/datamining/",i,"-mon0.csv.payload.broken_crc",sep=""), header=TRUE),
    #    lan_data 			= read.csv(file=paste("ofdmweak-1/sender=",broadcaster,"/datamining/",i,"-lan.csv",sep=""), header=TRUE),
    #    lan_payload 		= read.csv(file=paste("ofdmweak-1/sender=",broadcaster,"/datamining/",i,"-lan.csv.payload",sep=""),header=FALSE, sep = " ", dec='.'),
    athstats 			= read.csv(file=paste("ofdmweak-1/sender=",broadcaster,"/datamining/",i,"-athstats-global.csv",sep=""), header=TRUE,)
  )
  #  weak_on <- list (register, mon0_payload, mon0_broken_crc, mon0_broken_crc_payload, lan_data, lan_payload, athstats)
  #read traces where ofdm-weak-detection=off
  part0 <- list (
    register 			= read.csv(file=paste("ofdmweak-0/sender=",broadcaster,"/datamining/",i,"-register.csv",sep=""), header=TRUE),
    mon0			= read.csv(file=paste("ofdmweak-0/sender=",broadcaster,"/datamining/",i,"-mon0.csv",sep=""), header=TRUE, sep = ",", dec='.'),
    #    mon0_payload		= if (is.null(count.fields(file=paste("ofdmweak-0/sender=",broadcaster,"/datamining/",i,"-mon0.csv.payload",sep="")))){mon0_payload = 0}
    #      else{ mon0_payload	= read.csv(file=paste("ofdmweak-0/sender=",broadcaster,"/datamining/",i,"-mon0.csv.payload",sep=""), header=FALSE, sep = " ", dec='.')},
    mon0_broken_crc 		= read.csv(file=paste("ofdmweak-0/sender=",broadcaster,"/datamining/",i,"-mon0.csv.broken_crc",sep=""), header=TRUE),
    #    mon0_broken_crc_payload 	= read.csv(file=paste("ofdmweak-0/sender=",broadcaster,"/datamining/",i,"-mon0.csv.payload.broken_crc",sep=""), header=TRUE),
    #    lan_data 			= read.csv(file=paste("ofdmweak-0/sender=",broadcaster,"/datamining/",i,"-lan.csv",sep=""), header=TRUE),
    #    lan_payload 		= read.csv(file=paste("ofdmweak-0/sender=",broadcaster,"/datamining/",i,"-lan.csv.payload",sep=""),header=FALSE, sep = " ", dec='.'),
    athstats 			= read.csv(file=paste("ofdmweak-0/sender=",broadcaster,"/datamining/",i,"-athstats-global.csv",sep=""), header=TRUE,)
  )
  data[[i]] <- list (part_0 = part0, part_1 = part0)
}


#busy states die durch das sampling geteilt wurden addieren ... problem das die Summe kleiner ist als wirklich, da beim lesen MIC gestoppt wird
#Funktionen um samples zu filtern
SUM_double_sample <- function(datensatz) {
  m <- datensatz
  m_shifted  <- c(0,m[1:length(m)-1])									#vektor um Null an erster Stell erweitert (Verschiebung)
  index 	<- m * m_shifted > 0										#boolscher Index der true ist wo zwei oder mehr werte aufeinander folgen
  result 	<- m
  result[index] <- (m + m_shifted)[index]									#Summer der beiden aufeinanderfolgenden Werte
  result[index[2:length(index)]] 	<- c(0)									#löschen des ersten wertes der beiden
  return(result)
}

RM_double_sample <- function(datensatz) {
  m <- datensatz
  m_shifted	<- c(0,m[1:length(m)-1])									#vektor um Null an erster Stell erweitert (Verschiebung)
  index 	<- m * m_shifted > 0										#boolscher Index der true ist wo zwei oder mehr werte aufeinander folgen
  index_shifted	<- c(index[2:length(index)],FALSE)
  result	<- m
  result[index]	<- c(0)
  result[index_shifted]	<- c(0)											#verknüpfen der beiden indizes wo die aufeinanderfolgenden werte vorkommen
  return(result)
}


#Theoretische Busy states beim Senden in Abhängigkeit der Modulationsrate [MBit/sek] & Packetlänge [Byte]
CALC_tx_busy_ticks <- function(rate, packetlength) {
  r		<- rate
  p		<- packetlength
  result 	<- ( ceiling(((packetlength + 60)*8 + 22) / (rate*4) )*4 + 20 )*40
  return(result)
}

test <- function(df) {
  substitute(df)
}


PLOT_busy <- function (dataset, zz) {
  title <- substitute(dataset)
  zz <- ggplot( data = dataset$register) +
    geom_point( aes (x=timestamp - timestamp[1], y=mac_counter_diff, colour = "mac_clock"), size = 1, alpha=I(0.2), shape=20) +
    geom_point( aes (x=timestamp - timestamp[1], y=rx_counter_diff, colour = "rx_busy"), size = 3, alpha=I(0.8)) +
    geom_point( aes (x=timestamp - timestamp[1], y=ed_counter_diff, colour = "energy_busy"), size = 2, alpha=I(0.5)) +
    geom_point( aes (x=timestamp - timestamp[1], y=tx_counter_diff, colour = "tx_busy"), size = 2, alpha=I(0.5)) +
    geom_hline( yintercept=CALC_tx_busy_ticks(6, 128), colour = "grey10", size = 0.5, linetype = 3) +
    geom_hline( yintercept=CALC_tx_busy_ticks(9, 128), colour = "grey10", size = 0.5, linetype = 3) +
    geom_hline( yintercept=CALC_tx_busy_ticks(12, 128), colour = "grey10", size = 0.5, linetype = 3) +
    geom_hline( yintercept=CALC_tx_busy_ticks(18, 128), colour = "grey10", size = 0.5, linetype = 3) +
    geom_hline( yintercept=CALC_tx_busy_ticks(24, 128), colour = "grey10", size = 0.5, linetype = 3) +
    geom_hline( yintercept=CALC_tx_busy_ticks(36, 128), colour = "grey10", size = 0.5, linetype = 3) +
    geom_hline( yintercept=CALC_tx_busy_ticks(48, 128), colour = "grey10", size = 0.5, linetype = 3) +
    geom_hline( yintercept=CALC_tx_busy_ticks(54, 128), colour = "grey10", size = 0.5, linetype = 3) +
    geom_point( data=dataset$mon0_payload, aes(x=V1 - V1[1], y=50000, colour = "packets"), size = 5, alpha=I(1), shape=2) +
    ylim(0,170000) + 
    #		  xlim (400,410) +
    #		  scale_y_log10() +
    scale_colour_manual("MAC states", c("mac_clock"="black", "rx_busy"="green", "energy_busy"="blue", "tx_busy"="red", "packets"="black")) +
    ylab("register count [ticks]") + xlab("time [sec]") + opts(title=paste("MAC states from dataset ",title))
  return(zz)
}

PLOT_busy(data$tel$ofdmweak_on, tel)
