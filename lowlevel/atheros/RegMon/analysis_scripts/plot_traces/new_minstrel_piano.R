
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
#setwd("/Volumes/cracker/data/nfs/thomas/experiments/MINSTREL-PIANO-Messungen/1-link-Minstrel-Piano-new_version-hft2en-25.02.2012/data/datamining")
setwd("/Volumes/cracker/data/nfs/thomas/experiments/MINSTREL-BLUES-Messungen/1-link-Minstrel-Blues-tc2vws-28.03.2012/data/datamining")
#Einlesen
en_snr <- read.csv(file = "vws-snr-timeserie-v1.csv", header = T , sep = " ", dec='.')
en_thr <- read.csv(file = "vws-throughput-timeserie-v1.csv", header = T , sep = " ", dec='.')


setwd("/Volumes/cracker/data/nfs/thomas/experiments/MINSTREL-BLUES-Messungen/1-link-Minstrel-Blues-16-5_to_16-4-28.03.2012/data/datamining")
#Einlesen
en_snr <- read.csv(file = "_164-snr-timeserie-v1.csv", header = T , sep = " ", dec='.')
en_thr <- read.csv(file = "_164-throughput-timeserie-v1.csv", header = T , sep = " ", dec='.')



#SNR over time
ggplot(data = en_snr, 
       aes(x = time, y = snr + 102)) +
         #stat_smooth(fullrange=FALSE) +
         coord_cartesian(xlim=c(0,60)) +
         #geom_point(size=1.5, alpha=0.1, legend=TRUE) +
         #geom_boxplot(aes(group=round_any(time, 1, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
         geom_boxplot(aes(group=round_any(time, 1, floor)), fill=0, alpha=0.5) +
         #stat_smooth(fillrange=FALSE)
         
#thr over time
t1 = ggplot(data = en_thr, 
      aes(x = timeslot , y = bit.rate / 1000000)) +
        #stat_smooth(fullrange=FALSE) +
        geom_step(size=1, alpha=1, legend=TRUE) +
        coord_cartesian(xlim=c(0,1200)) +
        #stat_smooth(fullrange=FALSE) +
        #geom_point(size=1.5, alpha=0.1, legend=TRUE) +
        #geom_boxplot(aes(group=round_any(timeslot, 30, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
        geom_vline(xintercept = c(0), color="blue", size=0.5) +
        geom_vline(xintercept = c(300), color="blue", size=0.5) +
        geom_vline(xintercept = c(600,900,1200), color="blue", linetype="dashed", size=0.5) +
        #stat_smooth(fillrange=FALSE)
        scale_x_continuous(breaks = seq(0, 1300, by = 300)) +
        scale_y_continuous(breaks = seq(0, 20, by = 2)) +
        coord_cartesian(ylim=c(0,20)) +
        labs(x = "Time [sec]", y = "Throughput [MBit/s]") +
        theme_bw() +
        opts(strip.text.x = theme_text(size=12),
             strip.text.y = theme_text(size=12),
             axis.text.x = theme_text(size = 10, colour = "black"),
             axis.text.y = theme_text(size = 10, colour = "black"),
             #title ="Throughput / SNR with Minstrel Piano",
             plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
             strip.background = theme_rect(colour='darkgray', fill='lightgray'),
             legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
             legend.text=theme_text(colour="black", size=10, face="bold"),
             legend.background = theme_rect(),
             axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
             axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
             ) 

#thr over time
t2 = ggplot(data = en_thr, 
            aes(x = timeslot , y = bit.rate / 1000000)) +
              #stat_smooth(fullrange=FALSE) +
              #geom_step(size=1, alpha=1, legend=TRUE) +
              coord_cartesian(xlim=c(0,1200)) +
              stat_smooth(fullrange=FALSE) +
              #geom_point(size=1.5, alpha=0.1, legend=TRUE) +
              geom_boxplot(aes(group=round_any(timeslot, 30, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
              geom_vline(xintercept = c(0), color="blue", size=0.5) +
              geom_vline(xintercept = c(300), color="blue", size=0.5) +
              geom_vline(xintercept = c(600,900,1200), color="blue", linetype="dashed", size=0.5) +
              #stat_smooth(fillrange=FALSE)
              scale_x_continuous(breaks = seq(0, 1300, by = 300)) +
              scale_y_continuous(breaks = seq(0, 20, by = 2)) +
              coord_cartesian(ylim=c(0,20)) +
              labs(x = "Time [sec]", y = "Throughput [MBit/s]") +
              theme_bw() +
              opts(strip.text.x = theme_text(size=12),
                   strip.text.y = theme_text(size=12),
                   axis.text.x = theme_text(size = 10, colour = "black"),
                   axis.text.y = theme_text(size = 10, colour = "black"),
                   #title ="Throughput in scenarios with Minstrel Piano",
                   plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
                   strip.background = theme_rect(colour='darkgray', fill='lightgray'),
                   legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
                   legend.text=theme_text(colour="black", size=10, face="bold"),
                   legend.background = theme_rect(),
                   axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
                   axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
                   )


#SNR over time, noisefloor in trace-2 is -102
s1 = ggplot(data = subset(en_snr, datarate < 60 & retry.bit < 2), 
       aes(x = time, y = snr + 101)) +
         #stat_smooth(fullrange=FALSE) +
         #geom_point(size=0.5, alpha=0.3, position = "jitter", legend=TRUE) +
         geom_boxplot(aes(group=round_any(time, 30, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5, notch = TRUE) +
         #stat_summary(fun.data = mean, geom = "bar") +
         #stat_summary(fun.data = mean_cl_boot, geom = "pointrange", colour = "skyblue", size = 5) +
         coord_cartesian(xlim=c(0,1200)) +
         geom_vline(xintercept = c(0), color="blue", size=0.5) +
         geom_vline(xintercept = c(300), color="blue", size=0.5) +
         geom_vline(xintercept = c(600,900,1200), color="blue", linetype="dashed", size=0.5) +
         #stat_smooth(fillrange=FALSE) +
         scale_x_continuous(breaks = seq(0, 1200, by = 300)) +
         scale_y_continuous(breaks = seq(0, 43, by = 6)) +
         coord_cartesian(ylim=c(0,43)) +
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
              ) 


#mean(snr) over time
test = summarySE(en_snr, measurevar="snr", groupvars="round_any(time, 10, floor)")
names(test)[names(test)=="round_any(time, 10, floor)"] = "step"
#pd <- position_dodge(.1)

s2 = ggplot(data = test, aes(x = step +1, y = snr + 101 )) +
  geom_errorbar(aes(ymin=snr+101-ci, ymax=snr+101+ci), width=0.8, color='red') +
  geom_step(color="blue") +
  geom_point(shape=21, fille="white") +
  #geom_boxplot(aes(group=round_any(time, 2, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
  coord_cartesian(xlim=c(0,1200)) +
  geom_vline(xintercept = c(0), color="blue", size=0.5) +
  geom_vline(xintercept = c(300), color="blue", size=0.5) +
  geom_vline(xintercept = c(600,900,1200), color="blue", linetype="dashed", size=0.5) +
  #stat_smooth(fillrange=FALSE) +
  scale_x_continuous(breaks = seq(0, 1200, by = 300)) +
  scale_y_continuous(breaks = seq(0, 43, by = 6)) +
  coord_cartesian(ylim=c(0,43)) +
  labs(x = "Time [sec]", y = "SNR [dB]") +
  theme_bw() +
  opts(strip.text.x = theme_text(size=12),
       strip.text.y = theme_text(size=12),
       axis.text.x = theme_text(size = 10, colour = "black"),
       axis.text.y = theme_text(size = 10, colour = "black"),
       #title ="mean(SNR) - timeserie Minstrel Piano",
       plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
       strip.background = theme_rect(colour='darkgray', fill='lightgray'),
       legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
       legend.text=theme_text(colour="black", size=10, face="bold"),
       legend.background = theme_rect(),
       axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
       axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
       ) 

multiplot(t1,t2,s1,s2,cols=2)

# with points snr
ggplot(data = test, aes(x = step +1, y = snr + 104 )) +
  coord_cartesian(ylim=c(19,36)) +
  coord_cartesian(xlim=c(0,478)) +
  geom_point(data=en_snr,aes(x = time, y = snr + 104) , alpha=0.06, size=0.7, shape=1) +
  geom_errorbar(aes(ymin=snr+104-ci, ymax=snr+104+ci), width=0.8) +
  geom_step(color="blue", size=1.5) +
  geom_point(shape=21, fille="white") +
  #geom_boxplot(aes(group=round_any(time, 2, floor)),fill=0, outlier.colour = "red", outlier.size=1, alpha=0.5) +
  geom_vline(xintercept = c(120), color="blue", size=0.5) +
  geom_vline(xintercept = c(240,360), color="red", linetype="dashed", size=0.5) +
  scale_x_continuous(breaks = seq(0, 480, by = 60)) +
  scale_y_continuous(breaks = seq(18, 35, by = 3)) +
  labs(x = "Time [sec]", y = "SNR [dB]") +
  theme_bw() +
  opts(strip.text.x = theme_text(size=12),
       strip.text.y = theme_text(size=12),
       axis.text.x = theme_text(size = 10, colour = "black"),
       axis.text.y = theme_text(size = 10, colour = "black"),
       #title ="mean(SNR) - timeserie Minstrel Piano",
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
         geom_text(aes(x=34, y=7, label="Minstrel-Piano"),size=4, color="red") +
         geom_text(aes(x=33, y=3, label="Receiver: ED"),size=4, color="red") +
         geom_text(aes(x=66, y=3, label="Receiver: ED & PD"),size=4, color="red")
#geom_text(aes(x=93, y=3, label="Receiver: ED"),size=4, color="red")








#plot rates over time


p1 =  ggplot(en_snr, aes(x=time), ylim=c(1,100000)) +
    #xlim=c(1,480) +
    #coord_cartesian(xlim=c(0,478)) +
    #coord_cartesian(ylim=c(1,1000000)) +
    geom_histogram(aes(fill=factor(datarate), binwidth=round_any(time, 30, floor)), position="fill") +
    #geom_bar(aes(fill=factor(datarate)), position="fill") +
    #   geom_histogram(aes(fill=factor(datarate)),binwidth = 120, position="dodge") +
    #geom_histogram(aes(y= ..density.., fill=factor(datarate)),binwidth = 30, position="dodge") +
    #scale_fill_manual(values=c("#FF4040", "#00CD00", "#858585", "#C6E2FF")) +
    #scale_fill_manual(values=c("#111111", "#4F4F4F", "#7A7A7A", "#C2C2C2"), name="data\nrate") +
    #scale_fill_grey() +
    geom_vline(xintercept = c(0,300), color="blue", size=0.5) +
    geom_vline(xintercept = c(600,900,1200), color="red", linetype="dashed", size=0.5) +
    scale_x_continuous(breaks = seq(0, 1200, by = 120)) +
    #scale_y_continuous(breaks = seq(0, 1, by = 0.2)) +
    labs(x = "Time [sec]", y = "count of modulation rates") +
    theme_bw() +
    scale_y_log10() +
    geom_text(aes(x=55, y=200000, label="I"),size=4, color="blue") +
    geom_text(aes(x=170, y=200000, label="II"),size=4, color="red") +
    geom_text(aes(x=294, y=200000, label="III"),size=4, color="red") +
    geom_text(aes(x=415, y=200000, label="IV"),size=4, color="red") +
    facet_grid(. ~ datarate) +
    opts(legend.position="none") +
    opts(strip.text.x = theme_text(size=12),
         strip.text.y = theme_text(size=12),
         axis.text.x = theme_text(angle = 45, size = 8, colour = "black"),
         axis.text.y = theme_text(size = 10, colour = "black"),
         #title ="tx-rate distribution of Minstrel and Minstrel-Piano",
         plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
         strip.background = theme_rect(colour='darkgray', fill='lightgray'),
         legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
         legend.text=theme_text(colour="black", size=10, face="bold"),
         legend.background = theme_rect(),
         axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold"),
         axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 15, colour = "black", face="bold")
         )


ggsave(p1, file="bluse.png", width=11, height=8, dpi=600)




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
