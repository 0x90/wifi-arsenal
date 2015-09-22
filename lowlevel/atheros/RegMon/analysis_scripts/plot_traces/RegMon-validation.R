#notwendige Bibliotheken laden
require(ggplot2)
require(plyr)
library(reshape2)




#Arbeitspfad setzen
setwd("/Users/bluse/Desktop/trace_rigaer11.07.12/RegMon_validation/test-RegMon-sampling-accuracy-ath5k-Asus/datamining")                                                                                                      

cpu<- read.csv( file = "merged_cpu_distribution.txt", header = TRUE, sep=" ", dec=".", stringsAsFactors=FALSE )
tsf<- read.csv( file = "merged_tsf_distribution.txt", header = TRUE, sep=" ", dec=".", stringsAsFactors=FALSE, na.strings = "NA" )
ktime<- read.csv( file = "merged_ktime_distribution.txt", header = TRUE, sep=" ", dec=".", stringsAsFactors=FALSE )



ggplot(mtcars, aes(factor(cyl), prop.table(..count..) * 100)) + geom_bar()

geom_bar(aes(y=..count../sum(..count..)))



sum_tsf = summarySE(tsf, measurevar="tsf", groupvars="interval")

# SAMPLING ACCURACY based on TSF
ggplot( data=tsf, mapping = aes(x = d_tsf, y = freq) ) +
    geom_boxplot(aes(group = interval/1000), outlier.colour = "red", outlier.size = 1, alpha=0.3) +
  

ggplot(tsf, aes(x = d_tsf, weight = freq, y = ..density..)) +
    geom_histogram(binwidth=100, colour = "black") +
    facet_wrap(~ interval, ncol=2, scales = "free_y")
    
ggplot( data=tsf, mapping = aes(x = d_tsf, y = freq) ) +
  geom_histogram(binwidth=10)
  
  
  
         geom_bar(aes(group=interval))
         
         
         geom_point(size=1, alpha=0.3) +
         stat_smooth(fullrange=FALSE) 
       geom_boxplot(fill=0, outlier.colour = "red", outlier.size=, alpha=0.5)
       
         
         
         
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
