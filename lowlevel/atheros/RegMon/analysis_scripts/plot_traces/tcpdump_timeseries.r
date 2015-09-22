require(ggplot2)
require(xtable)


#Arbeitspfad setzen
setwd("/Volumes/cracker/data/nfs/thomas/experiments/noise-31.05.2011-nosynch-noise4-cca62-ofdmweak1-ch6/data/results")
#Einlesen
tcpdump_ts <- read.csv(file = "a-tcpdump-24h-int=10sec-phsall.csv", header = T , sep = ",")

#Arbeitspfad setzen
setwd("/Volumes/cracker/data/nfs/thomas/experiments/noise-31.05.2011-nosynch-noise4-cca62-ofdmweak1-ch6/data/merged-trace/aggregation")
#Einlesen
noise_ts <- read.csv(file = "all-nodes-1sec-noise-timeserie.csv", header = T , sep = "")
noise_ts <- subset(noise_ts, mean > -120 & !as.character(node) %in% as.character("en"))
#spezielle node auswaehlen
node_noise_ts <- subset(noise_ts, as.character(node) %in% as.character("a"))

#plot timeseries
  ggplot(data = tcpdump_ts, aes(x = timestamp / 3600, y = radiotap_wlan.bytes / 1024)) +
    #geom_point(size=0.9, alpha=0.4) +
    geom_smooth(aes(y = radiotap_wlan.bytes / 1024), colour="blue", alpha=0.4, pointsize=0.1) +
    geom_smooth(aes(y = radiotap_wlan_wlan_mgt.bytes / 1024), colour="red", alpha=0.4, pointsize=0.1) +
    geom_smooth(aes(y = radiotap_wlan_wlan_mgt_malformed.bytes / 1024), colour="green", alpha=0.4, pointsize=0.1) +
    geom_boxplot(aes(y = radiotap_wlan_data.bytes / 1024, group = round_any(timestamp, 600, floor)), 
             outlier.colour = "darkred", outlier.size = 2, alpha=0.3) +    
    geom_smooth(data = node_noise_ts, aes(x = timestamp/3600, y = 10 ^ (mean /10)*10^10), stat = "smooth", colour="yellow")  +
    scale_x_continuous(breaks = c(1,3,5,7,9,11,13,15,17,19,21,23), 
    labels=c("24:00", "2:00", "4:00", "6:00", "8:00", "10:00", "12:00", "14:00", "16:00", "18:00", "20:00", "22:00")) +
    coord_cartesian(xlim = c(0,24)) +
    coord_cartesian(ylim = c(0,400))

    geom_boxplot(aes(y = radiotap_wlan_data.bytes / 1024, group = round_any(timestamp, 1800, floor)), outlier.colour = "darkred", outlier.size = 2, alpha=0.3) +
    #stat_summary(fun.data = "mean_cl_boot", geom = "crossbar", colour = "red", width = 0.3) +
    geom_smooth(stat = "smooth", colour="blue") +
    #scale_y_continuous(breaks = seq(-120, -60, by = 2)) +
    scale_x_continuous(breaks = c(1,3,5,7,9,11,13,15,17,19,21,23), 
    labels=c("24:00", "2:00", "4:00", "6:00", "8:00", "10:00", "12:00", "14:00", "16:00", "18:00", "20:00", "22:00")) +
    coord_cartesian(xlim = c(0,24)) +

    labs(x = "hour of the day [hh:mm]", y = "noisefloor [dB]") +
    opts(axis.text.y = theme_text(hjust = 1, size = 8, colour = "black"),
              axis.text.x = theme_text(hjust = 0.5, size = 8, colour = "black"),
              axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              legend.position="none",
              title ="Noisefloor distribution in 24h on channel 6",
              plot.title=theme_text(colour="black", size=12, vjust = 1.5, hjust = 0.5),
              strip.text.x = theme_text(size=10, face='bold'),
              strip.background = theme_rect(colour='darkgray', fill='lightgray'))