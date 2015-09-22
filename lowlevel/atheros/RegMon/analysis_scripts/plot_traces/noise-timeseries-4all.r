require(ggplot2)
require(xtable)


#Arbeitspfad setzen
setwd("/Volumes/cracker/data/nfs/thomas/experiments/noise-31.05.2011-nosynch-noise4-cca62-ofdmweak1-ch6/data/merged-trace/aggregation")

#Einlesen
noise_ts <- read.csv(file = "all-nodes-1sec-noise-timeserie.csv", header = T , sep = "")
noise_ts <- subset(noise_ts, mean > -120 & !as.character(node) %in% as.character("en"))

#spezielle node auswaehlen
node_noise_ts <- subset(noise_ts, as.character(node) %in% as.character("af"))

#boxplots over time
print(
  ggplot(data = noise_ts, aes(x = timestamp/3600, y = mean)) +
    #geom_point(size=0.9, alpha=0.4) +
    geom_boxplot(aes(group = round_any(timestamp, 1800, floor)), outlier.colour = "darkred", outlier.size = 1, alpha=0.3) +
    #stat_summary(fun.data = "mean_cl_boot", geom = "crossbar", colour = "red", width = 0.3) +
    geom_smooth(stat = "smooth", colour="blue") +
    #scale_y_continuous(breaks = seq(-120, -60, by = 2)) +
    scale_x_continuous(breaks = c(1,3,5,7,9,11,13,15,17,19,21,23),
            labels=c("24:00", "2:00", "4:00", "6:00", "8:00", "10:00", "12:00", "14:00", "16:00", "18:00", "20:00", "22:00")) +
    coord_cartesian(xlim = c(0,24)) +
    coord_cartesian(ylim = c(-100,-78)) +
    labs(x = "hour of the day [hh:mm]", y = "noisefloor [dB]") +
    opts(axis.text.y = theme_text(hjust = 1, size = 8, colour = "black"),
              axis.text.x = theme_text(hjust = 0.5, size = 8, colour = "black"),
              axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              legend.position="none",
              title ="Noisefloor distribution in 24h on channel 6",
              plot.title=theme_text(colour="black", size=12, vjust = 1.5, hjust = 0.5),
              strip.text.x = theme_text(size=10, face='bold'),
              strip.background = theme_rect(colour='darkgray', fill='lightgray')) +
      facet_wrap(~ node, ncol=2)
)

#, scales = "free_y"

#TEST boxplots over time
ggplot(data = noise_ts, aes(x = round_any(timestamp,1800,floor), y = mean[mean >-110])) +
  geom_point(size=0.9, alpha=0.4) +
  stat_summary(fun.data = "mean_cl_boot", geom = "crossbar", colour = "red", width = 0.3) +
  geom_smooth(stat = "smooth", colour="blue")  



  layer(mapping = aes(x = timestamp/3600, y = mean[mean >-110], group = round_any(timestamp, 1800, floor)), 
        geom = "boxplot", alpha = 0.3 ) +
  layer(mapping = aes(x = timestamp/3600, y = max[max >-110]),
        geom = "line", stat = "smooth", color="red", alpha = 0.5) +
  layer(mapping = aes(x = timestamp/3600, y = min[min >-110]),
        geom = "smooth", color="green", alpha = 0.5) +
    scale_y_continuous(breaks = seq(-120, -60, by = 10)) +
    scale_x_continuous(breaks = c(1,3,5,7,9,11,13,15,17,19,21,23), 
      labels=c("24:00", "2:00", "4:00", "6:00", "8:00", "10:00", "12:00", "14:00", "16:00", "18:00", "20:00", "22:00")) +
    coord_cartesian(ylim = c(-105,-80), xlim = c(0,24)) +
      labs(x = "hour of the day [hh:mm]",
           y = "noisefloor [dB]") +
        opts(axis.text.y = theme_text(hjust = 1, size = 10, colour = "black"),
              axis.text.x = theme_text(hjust = 0.5, size = 10, colour = "black"),
              axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 17, colour = "black"),
              axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 17, colour = "black"),
              #legend.position="none",
              title ="Noisefloor distribution over 24h",
              plot.title=theme_text(colour="black", size=20, vjust = 1.5, hjust = 0.5),
              strip.text.x = theme_text(size=12, face='bold'),
              strip.background = theme_rect(colour='darkgray', fill='lightgray')) 


+
      facet_wrap(~ node, ncol=3, scales = "free_y")
 
m <- ggplot(data = af_register, aes(x = timestamp/3600, y = mean[mean >-110]))
m + geom_smooth(stat="identity")
m + stat_smooth() + geom_point(alpha=I(0.2))
             
             
#test
af_register$disp_mean <- round_any(af_register$mean, 1800, ceiling)
p <- ggplot(data = af_register, mapping = aes(x = timestamp, y = mean[mean >-110] ), geom = "line", colour="red")
p  + facet_wrap(. ~ af_register$disp_mean, nrow = 1)

ggplot() +
layer(
 data = af_register, mapping = aes(x = timestamp, y = mean[mean >-110] ),
 geom = "point", stat = "identity", alpha = 0.1
) +
layer(
 data = af_register, mapping = aes(x = timestamp, y = mean[mean >-110] ),
 geom = "smooth", stat = "smooth", color = "yellow"
) +  
layer(
 data = af_register, mapping = aes(x = timestamp, y = max[max >-110]),
 geom = "line", stat = "identity", color="red", alpha = 0.1
) +
layer(
 data = af_register, mapping = aes(x = timestamp[min >-110], y = min[min >-110]),
 geom = "line", stat = "identity", color="green", alpha = 0.1
) +
layer(data = ma_register, mapping = aes(x = timestamp, y = std - 110),
 geom = "line", stat = "identity", color="blue"
)



#testing



ggplot(data = noise_ts) +
layer(
 mapping = aes(x = timestamp, y = mean[mean >-110], colour=node ),
 geom = "smooth", stat = "smooth"
) +
layer(
 data = ma_register, mapping = aes(x = timestamp, y = mean[mean >-110] ),
 geom = "smooth", stat = "smooth", color = "coral"
) +
layer(
 data = eb_register, mapping = aes(x = timestamp, y = mean[mean >-110] ),
 geom = "smooth", stat = "smooth", color = "cyan"
) +
layer(
 data = tc_register, mapping = aes(x = timestamp, y = mean[mean >-110] ),
 geom = "smooth", stat = "smooth", color = "darkblue"
) + 
layer(
 data = c_register, mapping = aes(x = timestamp, y = mean[mean >-110] ),
 geom = "smooth", stat = "smooth", color = "darkgreen"
) +
layer(
 data = en_register, mapping = aes(x = timestamp, y = mean[mean >-110] ),
 geom = "smooth", stat = "smooth", color = "brown"
)+
layer(
 data = a_register, mapping = aes(x = timestamp, y = mean[mean >-110] ),
 geom = "smooth", stat = "smooth", color = "blueviolet"
) + 
layer(
 data = af_register, mapping = aes(x = timestamp, y = mean[mean >-110] ),
 geom = "line", stat = "smooth", color = "aquamarine"
) + 
layer(
 data = vws_register, mapping = aes(x = timestamp, y = mean[mean >-110] ),
 geom = "smooth", stat = "smooth", color = "darkgoldenrod1"
)
