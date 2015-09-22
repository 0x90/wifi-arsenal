require(ggplot2)
require(xtable)


#Arbeitspfad setzen
setwd("/Volumes/cracker/data/nfs/thomas/experiments/noise-31.05.2011-nosynch-noise4-cca62-ofdmweak1-ch6/data/merged-trace/aggregation")

hft_ewma <- read.csv(file="hft-60-sec-ewma.csv", header=FALSE, sep = ",")
hft_histogram <- read.csv(file="hft-24h-histogram.csv", header=FALSE, sep = ",")
ma_histogram <- read.csv(file="ma-24h-histogram.csv", header=FALSE, sep = ",")
eb_histogram <- read.csv(file="eb-24h-histogram.csv", header=FALSE, sep = ",")
histo <- list(hft_histogram, ma_histogram, eb_histogram)

hft_register <- read.csv(file="hft-10-sec-aggregation.csv", header=TRUE, sep = ",")
ma_register <- read.csv(file="ma-10-sec-aggregation.csv", header=TRUE, sep = ",")
eb_register <- read.csv(file="eb-10-sec-aggregation.csv", header=TRUE, sep = ",")
tc_register <- read.csv(file="tc-10-sec-aggregation.csv", header=TRUE, sep = ",")
c_register <- read.csv(file="c-10-sec-aggregation.csv", header=TRUE, sep = ",")
en_register <- read.csv(file="en-10-sec-aggregation.csv", header=TRUE, sep = ",")
a_register <- read.csv(file="a-10-sec-aggregation.csv", header=TRUE, sep = ",")
af_register <- read.csv(file="af-10-sec-aggregation.csv", header=TRUE, sep = ",")
vws_register <- read.csv(file="vws-10-sec-aggregation.csv", header=TRUE, sep = ",")

#histogram
 ggplot(hft_histogram, aes(x = as.factor(V1), y=V2)) + geom_histogram(binwidth=1) 
ggplot(hft_histogram, aes(x = as.factor(V1), y = V2)) + geom_histogram(binwidth=1) + scale_y_log10

m <- ggplot(hft_histogram) 
m + geom_histogram(aes(x = V1, weight=V2), colour = "darkgreen", fill = "white", binwidth=1)
m + geom_density(aes(x=V1, y=..density..),binwidth=1) + ylim(0,1)

#good histogram
ggplot(hft_histogram, aes(x = V1, weight=V2/sum(V2))) + stat_bin(aes(y=..density..),binwidth=1)
ggplot(hft_histogram, aes(x = V1, weight=V2/sum(V2))) + 
  geom_histogram(aes(y = ..density..), colour = "darkgreen", fill = "darkgray",binwidth=1) +
  geom_density(colour = "red")

#density plot for single node
m <- ggplot(hft_histogram) +
      geom_histogram(aes(x = V1, weight = V2/sum(V2), y = ..density..), colour = "darkgreen", fill = "darkgray",binwidth=1) +
      geom_density(aes(x = V1, weight = V2/sum(V2), y = ..density..), binwidth=1, colour="darkred") +
      ylim(0,0.5) + xlim(-100,-60) +
      labs(x = "noise in dB", y = "density") + 
      opts(legend.position="none") +
      opts(title ="Noise densities from a kernel density estimator")
m


df <- data.frame(x = rnorm(10, 0, 1), y = rnorm(10, 0, 2), z = rnorm(10, 2, 1.5))
df.m <- melt(df)


ggplot() +
layer(
 data = hft_register, mapping = aes(x = timestamp, y = mean[mean >-110] ),
 geom = "smooth", stat = "smooth", color="skyblue"
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

#boxplots over time
ggplot(data = af_register) +
  layer(mapping = aes(x = timestamp/3600, y = mean[mean >-110] ), 
        stat = "smooth", colour="blue") +
  layer(mapping = aes(x = timestamp/3600, y = mean[mean >-110], group = round_any(timestamp, 3600, floor)), 
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