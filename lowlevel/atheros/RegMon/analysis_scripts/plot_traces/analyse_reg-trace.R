#notwendige Bibliotheken laden
require(ggplot2)
require(plyr)
library(reshape2)

#Arbeitspfad setzen
setwd("/Users/bluse/Desktop/trace_rigaer11.07.12")                                                                                                      

#Daten einlesen
register_raw <- read.csv( file = "test1.csv", header = TRUE, sep=",", dec=".", stringsAsFactors=FALSE )

#filter fehlerhafte werte
register_raw = subset(register_raw, (register_raw$expected_mac_count - register_raw$mac_counter_diff) > 0 & (register_raw$mac_counter_diff / register_raw$expected_mac_count) > 0.5)

#delta vektoren in sekunden
timestamp  = register_raw$timestamp - register_raw$timestamp[1]
time_delta = c(diff(register_raw[,1],lag=1,diff=1),0)
mac_delta  = register_raw$mac_counter_diff / (40 * 10^6)
mac_sum    = cumsum(mac_delta)
tx_delta   = register_raw$tx_counter_diff / (40 * 10^6)
tx_sum     = cumsum(tx_delta)
rx_delta   = register_raw$rx_counter_diff / (40 * 10^6)
rx_sum     = cumsum(rx_delta)
ed_delta   = register_raw$ed_counter_diff / (40 * 10^6)
ed_sum     = cumsum(ed_delta)
mac_expected = register_raw$expected_mac_count / (40 * 10^6)
reset      = register_raw$potential_reset

#erstelle daten frame
register = data.frame(timestamp, time_delta, mac_delta, mac_sum, tx_delta, tx_sum, rx_delta, rx_sum, ed_delta, ed_sum, mac_expected, reset)

#reshape datafram to long format
register_long = melt(register,
                     id.vars=c("timestamp","time_delta"),
                     measure.vars=c("mac_delta","tx_delta","rx_delta","ed_delta")
                     )
                     
#histogram mac time
ggplot(data = register, aes(x = time_delta)) + geom_area(aes(y = ..ndensity.. ), binwidth=0.01, stat = "bin")
ggplot(data = register, aes(x = mac_delta)) + geom_area(aes(y = ..ndensity.. ), binwidth=0.00001, stat = "bin")


#Güte mac counts
ggplot(data=register, aes(x=mac_sum, y=mac_delta)) +  geom_point(size=1, alpha=0.3)

#Güte der timestamp funktion
ggplot(data=register, aes(x=timestamp, y=time_delta)) +  geom_point(size=1, alpha=0.3)

#Güte mac counts
ggplot(data=register, aes(x=mac_sum, y=time_delta - mac_delta)) +  geom_point(size=1, alpha=0.3)


ggplot( data=register_long, aes( x=timestamp ) ) +
  geom_point( aes(y=value, color=variable) )
  
  
  geom_area( aes(y=..count..,fill=variable), stat = "bin", binwidth = 1, position = "stack" ) 


+
  coord_cartesian(ylim=c(0,100)) +
