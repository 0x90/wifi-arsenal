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

require(ggplot2)
require(xtable)

#Arbeitspfad setzen
setwd("/Users/bluse/Desktop/bowl_traces/Broadcast-OLSR-21.03.2012/")

#Einlesen
olsr_outdoor <- read.csv(file = "bowl-asus-outdoor-olsr_links-per-rate-power-sens.csv", header = TRUE , sep = " ")
olsr_indoor <- read.csv(file = "bowl-asus-indoor-olsr_links-per-rate-power-sens.csv", header = TRUE , sep = " ")

outdoor = ggplot(data=subset(olsr_outdoor, cost <= 10)) +
  geom_histogram(aes(x=rate, fill =as.factor(rate))) + 
  scale_x_continuous(breaks = c(6,9,12,18,24,36,48,54)) +
  scale_y_continuous(breaks = seq(0, 140, by = 30)) +
  labs(x = "802.11 Bitrate", y = "Number of OLSR Links") +
  theme_bw() +
  opts(strip.text.x = theme_text(size=10),
       strip.text.y = theme_text(size=10),
       axis.text.x = theme_text(size = 7, colour = "black"),
       axis.text.y = theme_text(size = 8, colour = "black"),
       title ="outdoor",
       plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
       strip.background = theme_rect(colour='darkgray', fill='lightgray'),
       legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
       legend.text=theme_text(colour="black", size=10, face="bold"),
       legend.background = theme_rect(),
       axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 12, colour = "black", face="bold"),
       axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 12, colour = "black", face="bold")
       ) +
  scale_colour_hue(name="Data\nRate") +
  opts(legend.position="none") +
  facet_grid(sensivity ~ power)

indoor = ggplot(data=subset(olsr_indoor, cost <= 10)) +
  geom_histogram(aes(x=rate, fill =as.factor(rate))) + 
  scale_x_continuous(breaks = c(6,9,12,18,24,36,48,54)) +
  scale_y_continuous(breaks = seq(0, 60, by = 20)) +
  labs(x = "802.11 Bitrate", y = "Number of OLSR Links") +
  theme_bw() +
  opts(strip.text.x = theme_text(size=10),
       strip.text.y = theme_text(size=10),
       axis.text.x = theme_text(size = 7, colour = "black"),
       axis.text.y = theme_text(size = 8, colour = "black"),
       title ="indoor",
       plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
       strip.background = theme_rect(colour='darkgray', fill='lightgray'),
       legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
       legend.text=theme_text(colour="black", size=10, face="bold"),
       legend.background = theme_rect(),
       axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 12, colour = "black", face="bold"),
       axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 12, colour = "black", face="bold")
       ) +
  scale_colour_hue(name="Data\nRate") +
  opts(legend.position="none") +
facet_grid(sensivity ~ power)

multiplot(outdoor, indoor,cols=1)



outdoor = ggplot(data=subset(olsr_outdoor, cost <= 10)) +
  geom_histogram(aes(x=power, fill =as.factor(power))) + 
  scale_x_continuous(breaks = seq(0, 21, by = 3)) +
  scale_y_continuous(breaks = seq(0, 140, by = 30)) +
  labs(x = "TX-Power [dBm]", y = "Number of OLSR Links") +
  theme_bw() +
  opts(strip.text.x = theme_text(size=10),
       strip.text.y = theme_text(size=10),
       axis.text.x = theme_text(size = 7, colour = "black"),
       axis.text.y = theme_text(size = 8, colour = "black"),
       title ="outdoor",
       plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
       strip.background = theme_rect(colour='darkgray', fill='lightgray'),
       legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
       legend.text=theme_text(colour="black", size=10, face="bold"),
       legend.background = theme_rect(),
       axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 12, colour = "black", face="bold"),
       axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 12, colour = "black", face="bold")
       ) +
         scale_colour_hue(name="Data\nRate") +
         opts(legend.position="none") +
         facet_grid(sensivity ~ rate)

indoor = ggplot(data=subset(olsr_indoor, cost <= 10)) +
  geom_histogram(aes(x=power, fill =as.factor(power))) + 
  scale_x_continuous(breaks = seq(0, 21, by = 3)) +
  scale_y_continuous(breaks = seq(0, 60, by = 20)) +
  labs(x = "TX-Power [dBm]", y = "Number of OLSR Links") +
  theme_bw() +
  opts(strip.text.x = theme_text(size=10),
       strip.text.y = theme_text(size=10),
       axis.text.x = theme_text(size = 7, colour = "black"),
       axis.text.y = theme_text(size = 8, colour = "black"),
       title ="indoor",
       plot.title=theme_text(colour="black", face="bold", size=13, vjust = 1.5, hjust = 0.5),
       strip.background = theme_rect(colour='darkgray', fill='lightgray'),
       legend.title=theme_text(colour="black", size=11, hjust=-.1, face="bold"),
       legend.text=theme_text(colour="black", size=10, face="bold"),
       legend.background = theme_rect(),
       axis.title.y = theme_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 12, colour = "black", face="bold"),
       axis.title.x = theme_text(vjust = 0.2, hjust = 0.5, size = 12, colour = "black", face="bold")
       ) +
         scale_colour_hue(name="Data\nRate") +
         opts(legend.position="none") +
         facet_grid(sensivity ~ rate)

multiplot(outdoor, indoor,cols=1)

#usefull functions

stat_sum_single <- function(fun, geom="point", ...) { 
  stat_summary(fun.y=fun, colour="red", geom=geom, size = 3, ...) 
} 

stat_sum_df <- function(fun, geom="crossbar", ...) { 
  stat_summary(fun.data=fun, colour="red", geom=geom, width=0.2, ...) 
}