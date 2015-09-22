
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

require(ggplot2)
require(xtable)

#Arbeitspfad setzen
setwd("/Volumes/cracker/data/nfs/thomas/experiments/MINSTREL-BLUES-Messungen/2-links-Minstrel-Blues-@Bennis-home-11.07.2012/data/datamining")

#Einlesen
asterix_snr_20_laptop <- read.csv(file = "proto=tcp-packetsize=1420-weight=20-channel=1-mon1-snr-timeserie_laptop.csv", header = T, sep = " ", dec='.')
asterix_snr_20_netbook <- read.csv(file = "proto=tcp-packetsize=1420-weight=20-channel=1-mon1-snr-timeserie_netbook.csv", header = T, sep = " ", dec='.')
asterix_thr_20_laptop <- read.csv(file = "proto=tcp-packetsize=1420-weight=20-channel=1-mon1-throughput-timeserie_laptop.csv", header = T, sep = " ", dec='.')
asterix_thr_20_netbook <- read.csv(file = "proto=tcp-packetsize=1420-weight=20-channel=1-mon1-throughput-timeserie_netbook.csv", header = T, sep = " ", dec='.')
asterix_snr_40_laptop <- read.csv(file = "proto=tcp-packetsize=1420-weight=40-channel=1-mon1-snr-timeserie_laptop.csv", header = T, sep = " ", dec='.')
asterix_snr_40_netbook <- read.csv(file = "proto=tcp-packetsize=1420-weight=40-channel=1-mon1-snr-timeserie_netbook.csv", header = T, sep = " ", dec='.')
asterix_thr_40_laptop <- read.csv(file = "proto=tcp-packetsize=1420-weight=40-channel=1-mon1-throughput-timeserie_laptop.csv", header = T, sep = " ", dec='.')
asterix_thr_40_netbook <- read.csv(file = "proto=tcp-packetsize=1420-weight=40-channel=1-mon1-throughput-timeserie_netbook.csv", header = T, sep = " ", dec='.')
asterix_snr_100_laptop <- read.csv(file = "proto=tcp-packetsize=1420-weight=100-channel=1-mon1-snr-timeserie_laptop.csv", header = T, sep = " ", dec='.')
asterix_snr_100_netbook <- read.csv(file = "proto=tcp-packetsize=1420-weight=100-channel=1-mon1-snr-timeserie_netbook.csv", header = T, sep = " ", dec='.')
asterix_thr_100_laptop <- read.csv(file = "proto=tcp-packetsize=1420-weight=100-channel=1-mon1-throughput-timeserie_laptop.csv", header = T, sep = " ", dec='.')
asterix_thr_100_netbook <- read.csv(file = "proto=tcp-packetsize=1420-weight=100-channel=1-mon1-throughput-timeserie_netbook.csv", header = T, sep = " ", dec='.')

#thr over time
ggplot(data = subset(asterix_thr_100_netbook, timeslot > 2 & timeslot <= 600),
      aes(x = timeslot, y = bit.rate / 1000000)) +
        #stat_smooth(fullrange=FALSE) +
        #geom_step(size=0.1, alpha=0.3, legend=TRUE) +
        coord_cartesian(ylim=c(0,13)) +
        stat_smooth(fullrange=FALSE) +
        #geom_point(size=3.5, alpha=0.5, legend=TRUE) +
        geom_boxplot(aes(group=round_any(timeslot, 75, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
        geom_vline(xintercept = c(150), color="blue", size=0.5) +
        geom_vline(xintercept = c(300), color="red", linetype="dashed", size=0.5) +
        geom_vline(xintercept = c(450), color="blue", size=0.5) +
        geom_vline(xintercept = c(600), color="red", linetype="dashed", size=0.5) +
        #stat_smooth(fillrange=FALSE)
        scale_x_continuous(breaks = c(50,100,150,200,250,300,350,400,450,500,550,600)) +
        scale_y_continuous(breaks = seq(0, 13, by = 2)) +
        labs(x = "Time [sec]", y = "Throughput [MBit/s]") +
        theme_bw() +
        opts(strip.text.x = theme_text(size=12),
             strip.text.y = theme_text(size=12),
             axis.text.x = theme_text(size = 10, colour = "black"),
             axis.text.y = theme_text(size = 10, colour = "black"),
             #title ="Throughput 0..26  Minstrel full power, 26..56, Piano sens-low, 56..86 Piano sens-high",
             plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
             strip.background = theme_rect(colour='darkgray', fill='lightgray'),
             legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
             legend.text=theme_text(colour="black", size=10, face="bold"),
             legend.background = theme_rect(),
             axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
             axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
             ) +
               geom_text(aes(x=10, y=2, label="Minstrel fixed power"),size=4, color="blue") +
               geom_text(aes(x=7, y=1, label="Receiver: ED"),size=4, color="blue") +
               geom_text(aes(x=37, y=2, label="Minstrel-Piano"),size=4, color="red") +
               geom_text(aes(x=36, y=1, label="Receiver: ED"),size=4, color="red") +
               geom_text(aes(x=69, y=1, label="Receiver: ED & PD"),size=4, color="red")
#geom_text(aes(x=92, y=0, label="Receiver: ED"),size=4, color="red")


#SNR over time, noisefloor in trace-2 is -100
ggplot(data = subset(asterix_snr_100_laptop, time <= 600), 
       aes(x = time, y = snr + 101)) +
         #coord_cartesian(xlim=c(0,85)) +
         coord_cartesian(ylim=c(0,43)) +
         #stat_smooth(fullrange=FALSE) +
         #geom_point(size=1.5, alpha=0.1, legend=TRUE) +
         geom_boxplot(aes(group=round_any(time, 10, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
         geom_vline(xintercept = c(150), color="blue", size=0.5) +
         geom_vline(xintercept = c(300), color="red", linetype="dashed", size=0.5) +
         geom_vline(xintercept = c(450), color="blue", size=0.5) +
         geom_vline(xintercept = c(600), color="red", linetype="dashed", size=0.5) +
         #stat_smooth(fillrange=FALSE)
         scale_x_continuous(breaks = c(50,100,150,200,250,300,350,400,450,500,550,600)) +
         scale_y_continuous(breaks = seq(0, 43, by = 3)) +
         labs(x = "Time [sec]", y = "SNR [dB]") +
         theme_bw() +
         opts(strip.text.x = theme_text(size=12),
              strip.text.y = theme_text(size=12),
              axis.text.x = theme_text(size = 10, colour = "black"),
              axis.text.y = theme_text(size = 10, colour = "black"),
              #title ="SNR - timeserie Minstrel Piano",
              plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
              strip.background = theme_rect(colour='darkgray', fill='lightgray'),
              legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
              legend.text=theme_text(colour="black", size=10, face="bold"),
              legend.background = theme_rect(),
              axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
              axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
              ) +
                geom_text(aes(x=10, y=7, label="Minstrel fixed power"),size=4, color="blue") +
                geom_text(aes(x=7, y=3, label="Receiver: ED"),size=4, color="blue") +
                geom_text(aes(x=37, y=7, label="Minstrel-Piano"),size=4, color="red") +
                geom_text(aes(x=36, y=3, label="Receiver: ED"),size=4, color="red") +
                geom_text(aes(x=69, y=3, label="Receiver: ED & PD"),size=4, color="red")
#geom_text(aes(x=93, y=3, label="Receiver: ED"),size=4, color="red") 


#mean(snr) over time HFT-EN
sum_en = summarySE(asterix_snr_20_laptop, measurevar="snr", groupvars="round_any(time, 5, floor)")
names(sum_en)[names(sum_en)=="round_any(time, 5, floor)"] = "step"

p1 = ggplot(data = sum_en, aes(x = step +1, y = snr + 101 )) +
  #coord_cartesian(xlim=c(0,85)) +
  coord_cartesian(ylim=c(24,43)) +
  geom_errorbar(aes(ymin=snr+103-ci, ymax=snr+103+ci), width=0.8) +
  geom_step(color="black", size=0.8) +
  geom_point(shape=21, fille="white") +
  #geom_boxplot(aes(group=round_any(time, 2, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
  geom_vline(xintercept = c(150,300,450,600), color="blue", size=0.5, linetype="dashed") +
  #geom_vline(xintercept = c(240), color="red", linetype="dashed", size=0.5) +
  scale_x_continuous(breaks = seq(0, 600, by =30)) +
  scale_y_continuous(breaks = seq(24, 43, by = 1)) +
  labs(x = "Time [sec]", y = "SNR [dB]") +
  theme_bw() +
  opts(strip.text.x = theme_text(size=12),
       strip.text.y = theme_text(size=12),
       axis.text.x = theme_text(size = 10, colour = "black"),
       axis.text.y = theme_text(size = 10, colour = "black"),
       title ="mean(SNR) - timeserie Minstrel Piano",
       plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
       strip.background = theme_rect(colour='darkgray', fill='lightgray'),
       legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
       legend.text=theme_text(colour="black", size=10, face="bold"),
       legend.background = theme_rect(),
       axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
       axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
       ) 


#mean(snr) over time EB-A
sum_a = summarySE(a_snr, measurevar="snr", groupvars="round_any(time, 5, floor)")
names(sum_a)[names(sum_a)=="round_any(time, 5, floor)"] = "step"

p2 = ggplot(data = sum_a, aes(x = step +1, y = snr + 103 )) +
  #coord_cartesian(xlim=c(0,85)) +
  coord_cartesian(ylim=c(24,36)) +
  geom_errorbar(aes(ymin=snr+103-ci, ymax=snr+103+ci), width=0.8) +
  geom_step(color="black", size=0.8) +
  geom_point(shape=21, fille="white") +
  #geom_boxplot(aes(group=round_any(time, 2, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
  geom_vline(xintercept = c(120,240,360,460,600,720), color="blue", size=0.5, linetype="dashed") +
  #geom_vline(xintercept = c(240), color="red", linetype="dashed", size=0.5) +
  scale_x_continuous(breaks = seq(0, 900, by =60)) +
  scale_y_continuous(breaks = seq(24, 36, by = 1)) +
  labs(x = "Time [sec]", y = "SNR [dB]") +
  theme_bw() +
  opts(strip.text.x = theme_text(size=12),
       strip.text.y = theme_text(size=12),
       axis.text.x = theme_text(size = 10, colour = "black"),
       axis.text.y = theme_text(size = 10, colour = "black"),
       title ="mean(SNR) - timeserie Minstrel Piano",
       plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
       strip.background = theme_rect(colour='darkgray', fill='lightgray'),
       legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
       legend.text=theme_text(colour="black", size=10, face="bold"),
       legend.background = theme_rect(),
       axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
       axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
       )

#mean thr over time HFT-EN
sum_thr = summarySE(asterix_thr_100_netbook, measurevar="bit.rate", groupvars="round_any(timeslot, 10, floor)")
names(sum_thr)[names(sum_thr)=="round_any(timeslot, 10, floor)"] = "step"
p3 = ggplot(data = sum_thr, 
       aes(x = step , y = bit.rate / 1000000)) +
         #stat_smooth(fullrange=FALSE) +
         geom_errorbar(aes(ymin=bit.rate / 1000000 - ci / 1000000, ymax=bit.rate / 1000000 + ci / 1000000), width=0.8) +
         geom_step(color="blue", size=0.8) +
         coord_cartesian(ylim=c(0,13)) +
         geom_point(shape=21, fille="white") +
         #stat_smooth(fullrange=FALSE) +
         #geom_point(size=1.5, alpha=0.1, legend=TRUE) +
         #geom_boxplot(aes(group=round_any(timeslot, 30, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
         geom_vline(xintercept = c(150,300,450,600), color="blue", size=0.5, linetype="dashed") +
         #stat_smooth(fillrange=FALSE)
         scale_x_continuous(breaks = seq(0, 600, by =75)) +
         scale_y_continuous(breaks = seq(0, 14, by = 2)) +
         labs(x = "Time [sec]", y = "Throughput [MBit/s]") +
         theme_bw() +
         opts(strip.text.x = theme_text(size=12),
              strip.text.y = theme_text(size=12),
              axis.text.x = theme_text(size = 10, colour = "black"),
              axis.text.y = theme_text(size = 10, colour = "black"),
              #title ="Throughput 0..26  Minstrel full power, 26..56, Piano sens-low, 56..86 Piano sens-high",
              plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
              strip.background = theme_rect(colour='darkgray', fill='lightgray'),
              legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
              legend.text=theme_text(colour="black", size=10, face="bold"),
              legend.background = theme_rect(),
              axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
              axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
              )

#mean thr over time HFT-EN
sum_thr_100 = summarySE(asterix_thr_100_netbook, measurevar="bit.rate", groupvars="round_any(timeslot, 30, floor)")
names(sum_thr_100)[names(sum_thr_100)=="round_any(timeslot, 30, floor)"] = "step"
p4 = ggplot(data = sum_thr_100, 
            aes(x = step , y = bit.rate / 1000000)) +
              #stat_smooth(fullrange=FALSE) +
              geom_errorbar(aes(ymin=bit.rate / 1000000 - ci / 1000000, ymax=bit.rate / 1000000 + ci / 1000000), width=0.8) +
              geom_step(color="blue", size=0.8) +
              coord_cartesian(ylim=c(0,12)) +
              geom_point(shape=21, fille="white") +
              stat_smooth(fullrange=FALSE) +
              #geom_point(size=1.5, alpha=0.1, legend=TRUE) +
              #geom_boxplot(aes(group=round_any(timeslot, 30, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
              geom_vline(xintercept = c(150,300,450,600), color="blue", size=0.5, linetype="dashed") +
              #stat_smooth(fillrange=FALSE)
              scale_x_continuous(breaks = seq(0, 600, by =30)) +
              #scale_y_continuous(breaks = seq(24, 36, by = 1)) +
              labs(x = "Time [sec]", y = "Throughput [MBit/s]") +
              theme_bw() +
              opts(strip.text.x = theme_text(size=12),
                   strip.text.y = theme_text(size=12),
                   axis.text.x = theme_text(size = 10, colour = "black"),
                   axis.text.y = theme_text(size = 10, colour = "black"),
                   #title ="Throughput 0..26  Minstrel full power, 26..56, Piano sens-low, 56..86 Piano sens-high",
                   plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
                   strip.background = theme_rect(colour='darkgray', fill='lightgray'),
                   legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
                   legend.text=theme_text(colour="black", size=10, face="bold"),
                   legend.background = theme_rect(),
                   axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
                   axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
                   )


multiplot(p1, p2, p3, p4, cols=2)


total_snr_100 <- merge(asterix_snr_100_netbook, asterix_snr_100_laptop, by="step")
total_thr_100 <- merge(asterix_thr_100_netbook, asterix_thr_100_laptop, by="step")

t1 = ggplot(data = total_snr, aes(x = step +1)) +
  #coord_cartesian(xlim=c(0,85)) +
  coord_cartesian(ylim=c(24,36)) +
  geom_errorbar(aes(ymin=snr.x+103-ci.x, ymax=snr.x+103+ci.x), width=0.8) +
  geom_errorbar(aes(ymin=snr.y+104-ci.y, ymax=snr.y+104+ci.y), width=0.8) +
  geom_step(aes(y=snr.x+103),color="blue", size=0.8) +
  geom_step(aes(y=snr.y+104),color="red", size=0.8) +
  geom_point(aes(y=snr.x),shape=21, fille="white") +
  geom_point(aes(y=snr.y),shape=21, fille="white") +
  #geom_boxplot(aes(group=round_any(time, 2, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
  geom_vline(xintercept = c(120,240,360,460,600,720), color="blue", size=0.5, linetype="dashed") +
  #geom_vline(xintercept = c(240), color="red", linetype="dashed", size=0.5) +
  scale_x_continuous(breaks = seq(0, 900, by =60)) +
  scale_y_continuous(breaks = seq(24, 36, by = 1)) +
  labs(x = "Time [sec]", y = "SNR [dB]") +
  theme_bw() +
  opts(strip.text.x = theme_text(size=12),
       strip.text.y = theme_text(size=12),
       axis.text.x = theme_text(size = 10, colour = "black"),
       axis.text.y = theme_text(size = 10, colour = "black"),
       title ="mean(SNR) - timeserie Minstrel Piano",
       plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
       strip.background = theme_rect(colour='darkgray', fill='lightgray'),
       legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
       legend.text=theme_text(colour="black", size=10, face="bold"),
       legend.background = theme_rect(),
       axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
       axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
       )

t2 = ggplot(data = total_thr, aes(x = step +1)) +
  #coord_cartesian(xlim=c(0,85)) +
  #coord_cartesian(ylim=c(24,36)) +
  #geom_errorbar(aes(ymin=bit.rate.x+103-ci.x, ymax=bit.rate.x+103+ci.x), width=0.8) +
  #geom_errorbar(aes(ymin=bit.rate.y+104-ci.y, ymax=bit.rate.y+104+ci.y), width=0.8) +
  geom_step(aes(y=bit.rate.x / 1000000),color="blue", size=0.8) +
  geom_step(aes(y=bit.rate.y/ 1000000),color="red", size=0.8) +
  geom_step(aes(y=bit.rate.x/ 1000000 + bit.rate.y/ 1000000),color="black", size=1.2) +
  geom_point(aes(y=bit.rate.x/ 1000000),shape=21, fille="white") +
  geom_point(aes(y=bit.rate.y/ 1000000),shape=21, fille="white") +
  geom_point(aes(y=bit.rate.x/ 1000000 + bit.rate.y/ 1000000),shape=21, fille="white") +
  #geom_boxplot(aes(group=round_any(time, 2, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
  geom_vline(xintercept = c(120,240,360,460,600,720), color="blue", size=0.5, linetype="dashed") +
  #geom_vline(xintercept = c(240), color="red", linetype="dashed", size=0.5) +
  scale_x_continuous(breaks = seq(0, 900, by =60)) +
  #scale_y_continuous(breaks = seq(24, 36, by = 1)) +
  labs(x = "Time [sec]", y = "Throughput") +
  theme_bw() +
  opts(strip.text.x = theme_text(size=12),
       strip.text.y = theme_text(size=12),
       axis.text.x = theme_text(size = 10, colour = "black"),
       axis.text.y = theme_text(size = 10, colour = "black"),
       title ="mean(SNR) - timeserie Minstrel Piano",
       plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
       strip.background = theme_rect(colour='darkgray', fill='lightgray'),
       legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
       legend.text=theme_text(colour="black", size=10, face="bold"),
       legend.background = theme_rect(),
       axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
       axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
       )

multiplot(t1, t2, cols=1)





#plot rates over time

ggplot(subset(en_snr, time <=85), aes(time)) +
  coord_cartesian(xlim=c(0,85)) +
  geom_histogram(aes(fill=factor(datarate)),binwidth = 0.5, position="fill") +
  #scale_fill_manual(values=c("#FF4040", "#00CD00", "#858585", "#C6E2FF")) +
  #scale_fill_manual(values=c("#111111", "#4F4F4F", "#7A7A7A", "#C2C2C2"), name="data\nrate") +
  #scale_fill_grey() +
  geom_vline(xintercept = c(30), color="blue", size=0.5) +
  geom_vline(xintercept = c(60,90), color="red", linetype="dashed", size=0.5) +
  scale_x_continuous(breaks = c(30,60,90)) +
  scale_y_continuous(breaks = seq(0, 1, by = 0.2)) +
  labs(x = "Time [sec]", y = "rel. count") +
  theme_bw() +
  opts(strip.text.x = theme_text(size=12),
       strip.text.y = theme_text(size=12),
       axis.text.x = theme_text(size = 10, colour = "black"),
       axis.text.y = theme_text(size = 10, colour = "black"),
       title ="tx-rate distribution of Minstrel and Minstrel-Piano",
       plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
       strip.background = theme_rect(colour='darkgray', fill='lightgray'),
       legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
       legend.text=theme_text(colour="black", size=10, face="bold"),
       legend.background = theme_rect(),
       axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
       axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
       ) +
         geom_text(aes(x=11, y=0.98, label="Minstrel fixed power"),size=4, color="blue") +
         geom_text(aes(x=8, y=0.92, label="Receiver: ED"),size=4, color="blue") +
         geom_text(aes(x=36, y=0.98, label="Minstrel-Piano"),size=4, color="red") +
         geom_text(aes(x=35, y=0.92, label="Receiver: ED"),size=4, color="red") +
         geom_text(aes(x=68, y=0.92, label="Receiver: ED & PD"),size=4, color="red") +
         geom_text(aes(x=89, y=0.98, label="Receiver:"),size=4, color="red") +
         geom_text(aes(x=88, y=0.92, label="ED"),size=4, color="red")










##### test


ggplot(data = subset(en_snr, time <= 85), 
       aes(x = time, y = count(time))) +
         #coord_cartesian(xlim=c(0,85)) +
         #coord_cartesian(ylim=c(0,36)) +
         #stat_smooth(fullrange=FALSE) +
         #geom_point(size=1.5, alpha=0.1, legend=TRUE) +
         geom_boxplot(aes(group=round_any(time, 1, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
         geom_vline(xintercept = c(30), color="blue", size=0.5) +
         geom_vline(xintercept = c(60), color="red", linetype="dashed", size=0.5) +
         #stat_smooth(fillrange=FALSE)
         scale_x_continuous(breaks = c(0,10,20,30,40,50,60,70,80,90)) +
         scale_y_continuous(breaks = seq(0, 36, by = 6)) +
         labs(x = "Time [sec]", y = "SNR [dB]") +
         theme_bw() +
         opts(strip.text.x = theme_text(size=12),
              strip.text.y = theme_text(size=12),
              axis.text.x = theme_text(size = 10, colour = "black"),
              axis.text.y = theme_text(size = 10, colour = "black"),
              #title ="SNR - timeserie Minstrel Piano",
              plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
              strip.background = theme_rect(colour='darkgray', fill='lightgray'),
              legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
              legend.text=theme_text(colour="black", size=10, face="bold"),
              legend.background = theme_rect(),
              axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
              axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
              ) +
                geom_text(aes(x=10, y=7, label="Minstrel fixed power"),size=4, color="blue") +
                geom_text(aes(x=7, y=3, label="Receiver: ED"),size=4, color="blue") +
                geom_text(aes(x=37, y=7, label="Minstrel-Piano"),size=4, color="red") +
                geom_text(aes(x=36, y=3, label="Receiver: ED"),size=4, color="red") +
                geom_text(aes(x=69, y=3, label="Receiver: ED & PD"),size=4, color="red")
