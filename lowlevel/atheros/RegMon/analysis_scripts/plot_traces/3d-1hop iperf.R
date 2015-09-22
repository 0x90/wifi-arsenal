library(rgl)
require(ggplot2)
require(reshape)
require(xtable)

#Arbeitspfad setzen
setwd("/Volumes/cracker/data/nfs/thomas/experiments/1-link-iperf-en-2-hft-sense-rate-power-07.02.2012/data/datamining/")

m <- read.csv(file="iperf-summary-hft-2-en.csv", sep = "", head=TRUE)
high <- subset(m, m$sensivity=="high", select=c(rate,power,iperf_thr))
low <- subset(m, m$sensivity=="low")

#andere Messung
setwd("/Volumes/cracker/data/nfs/thomas/experiments/1-link-iperf-hft-2-en-sense-rate-power-07.02.2012/data/datamining/")
m <- read.csv(file="iperf-summary-hft-2-en.csv", sep = "", head=TRUE)
high <- subset(m, m$sensivity=="high", select=c(rate,power,iperf_thr))
low <- subset(m, m$sensivity=="low")

udp = read.csv(file="en-udp-data-snr-histogram.csv", sep = "", head=FALSE)
ack = read.csv(file="en-ack-snr-histogram.csv", sep = "", head=FALSE)
frames = read.csv(file="en-all-frames-histogram.csv", sep = "", head=FALSE)


ggplot(data=high, aes(x=power, y=iperf_thr, colour=as.factor(rate))) + 
  geom_point( size = 2) +
  geom_line( size = 1 ,alpha=I(0.6)) +
  #geom_smooth() +
  ylab("throughput [Bits per sec]") + xlab("adjusted tx-power [dBm]") + opts(title='weak = on - Throughput per power - rate combination')

ggplot(data=low, aes(x=power, y=iperf_thr, colour=as.factor(rate))) + 
  geom_point( size = 2) +
  geom_line( size = 1 ,alpha=I(0.6)) +
  #geom_smooth() +
  ylab("throughput [Bits per sec]") + xlab("adjusted tx-power [dBm]") + opts(title='weak = off - Throughput per power - rate combination')

ggplot(data=subset(udp, udp$V1=="high"), aes(x=V3, y=V4, colour=as.factor(V2))) +
  geom_point()


