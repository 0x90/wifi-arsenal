require(ggplot2)
require(xtable)
require(doBy)

#Arbeitspfad setzen
setwd("/Volumes/cracker/data/nfs/thomas/experiments/indoor-noise-17.07.2011-nosync-noise0-cca62-ofdm1-ch6/data/")

histogram <- read.csv(file="merged-trace/aggregation/tel-16-1-1-sec-histogram.csv", header=F, sep = ",")

#read histogramm summary file
histogram_all <- read.csv(file="merged-trace/aggregation/all-node-histogram.csv", header=TRUE, sep = " ")

#exclude en because 12 is a nicer grid than 13 nodes
histogram <- subset(histogram_all, noise>-120 & !as.character(node) %in% as.character("en"))

#extend the statistics per node
sumfun <- function(x, ...){
  c(mean=mean(x, ...), median=median(x, ...), sd=sd(x, ...), var=var(x, ...), length=length(x))
}
count_sum_per_node <- summaryBy(data=histogram, count ~ node, FUN=sum, na.rm=T)
noise_stats_per_node <- summaryBy(data=histogram, noise ~ node, FUN=sumfun, na.rm=T)

histogram <- merge(histogram,count_sum_per_node)

#test for a single node tel-16-1
ggplot(histogram, aes(x = V1, weight = V2, y = ..density..)) +
      geom_histogram(binwidth=1, colour = "black",) + 
      geom_density(aes(y=..scaled..), colour="darkred", legend=FALSE, adjust=1/3) +
      scale_y_continuous(breaks = seq(0, 1, by = 0.1)) +
      scale_x_continuous(breaks = seq(-110, -60, by = 10)) +
      labs(x = "measured noisefloor in 1dB bins [dB]",
           y = "density (kernel density estimator)") +
      coord_cartesian(xlim = c(min(histogram$V1),max(histogram$V1))) +
      coord_cartesian(ylim = c(0,1)) +
        opts(axis.text.y = theme_text(hjust = 1, size = 8, colour = "black"),
              axis.text.x = theme_text(hjust = 0.5, size = 8, colour = "black"),
              axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              legend.position="none",
              title ="Noisefloor density per node at channel 6",
              plot.title=theme_text(colour="black", size=12, vjust = 1.5, hjust = 0.5),
              strip.text.x = theme_text(size=10, face='bold'),
              strip.background = theme_rect(colour='darkgray', fill='lightgray'))


# PRINT EPS DENSTITY GRID PLOT
postscript(file="plots/noise-density-facetwrap-all-nodes-24h-ch6.eps", horizontal=F, onefile=F, height=5, width=5)
  print(
    ggplot(histogram, aes(x = noise, weight = count/count.sum, y = ..density.., fill = node)) +
      geom_histogram(binwidth=1, colour = "black",) + 
      scale_y_continuous(breaks = seq(0, 1, by = 0.1)) +
      scale_x_continuous(limits=c(-105,-70), breaks = seq(-110, -60, by = 10)) +
      labs(x = "measured noisefloor in 1dB bins [dB]",
           y = "density (kernel density estimator)") +
        opts(axis.text.y = theme_text(hjust = 1, size = 8, colour = "black"),
              axis.text.x = theme_text(hjust = 0.5, size = 8, colour = "black"),
              axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              legend.position="none",
              title ="Noisefloor density per node at channel 6",
              plot.title=theme_text(colour="black", size=12, vjust = 1.5, hjust = 0.5),
              strip.text.x = theme_text(size=10, face='bold'),
              strip.background = theme_rect(colour='darkgray', fill='lightgray')) +
      facet_wrap(~ node, ncol=3, scales = "free_y")
  )
dev.off()

#histogramm ueber alle nodes in FARBE
postscript(file="plots/noise-density-all-nodes-24h-ch6-color.eps", horizontal=F, onefile=F, height=5, width=5)
  print(
    ggplot(histogram, aes(x = noise)) +
      geom_histogram(aes(weight = count/sum(as.numeric(count)), y = ..density.., fill = node), binwidth = 1) +
      geom_histogram(aes(weight = count/sum(as.numeric(count)), y = ..density.., fill = node), 
                     colour = "black", binwidth = 1, legend=FALSE) +
      geom_density(aes(weight = count/sum(as.numeric(count)), y=..scaled..), colour="darkred", legend=FALSE, adjust=1/3) +
      scale_y_continuous(breaks = seq(0, 1.8, by = 0.1)) +
      scale_x_continuous(limits=c(-105,-70), breaks = seq(-110, -60, by = 5)) +
      labs(x = "measured noisefloor in 1dB bins [dB]",
           y = "density (kernel density estimator)") +
      geom_text(aes(x = -101, y=1.45, label = "*kernel density estimator"), size = 2, colour = "darkred") +
        opts(axis.text.y = theme_text(hjust = 1, size = 8, colour = "black"),
              axis.text.x = theme_text(hjust = 0.5, size = 8, colour = "black"),
              axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              title ="Noisefloor density including all nodes at channel 6",
              plot.title=theme_text(colour="black", size=12, vjust = 1.5, hjust = 0.5),
              strip.text.x = theme_text(size=10, face='bold'),
              strip.background = theme_rect(colour='darkgray', fill='lightgray'))
  )
dev.off()

#histogramm ueber alle nodes IN BLACK&WHITE
postscript(file="plots/noise-density-all-nodes-24h-ch6-blackwhite.eps", horizontal=F, onefile=F, height=5, width=5)
  print(
    ggplot(histogram, aes(x = noise)) +
      geom_histogram(aes(weight = count/sum(as.numeric(count)), y = ..density.., fill = node), binwidth = 1) +
      geom_histogram(aes(weight = count/sum(as.numeric(count)), y = ..density.., fill = node), 
                     colour = "black", binwidth = 1, legend=FALSE) +
      scale_fill_grey() +
      geom_density(aes(weight = count/sum(as.numeric(count)), y=..scaled..), colour="darkred", legend=FALSE, adjust=1/3) +
      scale_y_continuous(breaks = seq(0, 1.8, by = 0.1)) +
      scale_x_continuous(limits=c(-105,-70), breaks = seq(-110, -60, by = 5)) +
      labs(x = "measured noisefloor in 1dB bins [dB]",
           y = "density (kernel density estimator)") +
      geom_text(aes(x = -101, y=1.45, label = "*kernel density estimator"), size = 2, colour = "darkred") +
        opts(axis.text.y = theme_text(hjust = 1, size = 8, colour = "black"),
              axis.text.x = theme_text(hjust = 0.5, size = 8, colour = "black"),
              axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              title ="Noisefloor density including all nodes at channel 6",
              plot.title=theme_text(colour="black", size=12, vjust = 1.5, hjust = 0.5),
              strip.text.x = theme_text(size=10, face='bold'),
              strip.background = theme_rect(colour='darkgray', fill='lightgray'))
  )
dev.off()


#areaplots ueber alle nodes IN COLOR oder BLACK&WHITE
postscript(file="plots/noise-density-area-all-nodes-24h-ch6-color.eps", horizontal=F, onefile=F, height=5, width=5)
  print(
    ggplot(histogram, aes(noise, weight = count/sum(as.numeric(count)), fill = node)) +
      #scale_fill_grey() +
      geom_density(aes(y = ..density..), binwidth=1, alpha=1, position = "stack", adjust=1/5, ) +
      scale_y_continuous(breaks = seq(0, 1.8, by = 0.025)) +
      scale_x_continuous(limits=c(-105,-70), breaks = seq(-110, -60, by = 5)) +
      #geom_text(aes(x = -101, y=0.12, label = "*density shown as stacked"), size = 2, colour = "black") +
      labs(x = "measured noisefloor [dB]",
           y = "density (kernel density estimator)") +
         opts(axis.text.y = theme_text(hjust = 1, size = 8, colour = "black"),
              axis.text.x = theme_text(hjust = 0.5, size = 8, colour = "black"),
              axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              title ="Noisefloor density about all node at channel 6",
              plot.title=theme_text(colour="black", size=12, vjust = 1.5, hjust = 0.7),
              strip.text.x = theme_text(size=10, face='bold'),
              strip.background = theme_rect(colour='darkgray', fill='lightgray'))
  )
dev.off()
    
# wieviele node haben gleiche noise werte
equal_noise <- ddply(histogram, .(noise), summarise, freq=length(noise))
postscript(file="plots/equal-noise-at-nodes-24h-ch6-blackwhite.eps", horizontal=F, onefile=F, height=5, width=5)
  print(
    ggplot(equal_noise, aes(x=noise, weight=freq)) +
      scale_fill_grey() +
      geom_bar(binwidth=1,alpha=0.9) +
          scale_y_continuous(breaks = seq(0, 1.8, by = 0.1)) +
      scale_x_continuous(limits=c(-105,-70), breaks = seq(-110, -60, by = 5)) +
      labs(x = "measured noisefloor [dB]",
           y = "density (kernel density estimator)") +
        opts(axis.text.y = theme_text(hjust = 1, size = 8, colour = "black"),
              axis.text.x = theme_text(hjust = 0.5, size = 8, colour = "black"),
              axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 10, colour = "black"),
              title ="Noisefloor density about all node at channel 6",
              plot.title=theme_text(colour="black", size=12, vjust = 1.5, hjust = 0.5),
              strip.text.x = theme_text(size=10, face='bold'),
              strip.background = theme_rect(colour='darkgray', fill='lightgray'))
  )
dev.off()

