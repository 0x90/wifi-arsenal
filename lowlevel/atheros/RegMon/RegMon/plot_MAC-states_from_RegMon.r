#!/usr/bin/Rscript --vanilla

library(ggplot2)
library(reshape2)
library(scales)

label_wrap <- function(variable, value) {
    laply(strwrap(as.character(value), width=5, simplify=FALSE), paste, collapse="\n")
}

all_mac <- read.csv(file="stdin",header = T, sep = " ", dec='.')
all_mac <- melt(all_mac, id=c("ktime"), measure=c("d_tx","d_rx","d_idle","d_others"),variable_name = "mac_states")

max_x <- max(all_mac$ktime/1000000000)

p1 = ggplot(data=all_mac, aes (x=ktime/1000000000)) +
    geom_histogram(aes(fill=factor(variable), weight=abs(value)), position="fill", binwidth = 1) +
    geom_hline(yintercept = seq(0,1,0.25), color="grey50", linetype="dashed", size=0.3) +
    geom_hline(yintercept = seq(0.125,1,0.25), color="grey50", linetype="dotted", size=0.3) +
    geom_vline(xintercept = seq(0,max_x, by = round(max_x/5)), color="grey50", linetype="dashed", size=0.3) +
    geom_vline(xintercept = seq(max_x/10,max_x, by = round(max_x/5)), color="grey50", linetype="dotted", size=0.3) +
    scale_y_continuous(labels = percent_format()) +
    scale_x_continuous(limits=c(0, max_x), breaks = seq(0, max_x, by = round(max_x/5)), minor_breaks = seq(0, max_x, by = round(max_x/10))) +
    labs(x = "Time [s]", y = "relative dwell time [%]") +
    theme_bw() +
    labs(title = "Distribution of MAC-States over Time") +
    theme(strip.text.x = element_text(size=12),
        strip.text.y = element_text(size=9),
        axis.text.x = element_text(size = 15, colour = "black"),
        axis.text.y = element_text(size = 15, colour = "black"),
        plot.title=element_text(colour="black", face="plain", size=20, vjust = 1.5, hjust = 0.5),
        plot.title = element_text(size = 14),
        strip.background = element_rect(colour='grey30', fill='grey80'),
        legend.title=element_text(colour="black", size=16, hjust=-.1, face="plain"),
        legend.text=element_text(colour="black", size=15, face="plain"),
        legend.background = element_rect(),
        axis.title.y = element_text(angle = 90, vjust = 0.2, hjust = 0.5, size = 18, colour = "black", face="plain"),
        axis.title.x = element_text(vjust = 0.2, hjust = 0.5, size = 18, colour = "black", face="plain")
    ) +
    scale_fill_manual(values=c("#F55A5A", "#32B2FF", "#F5DA81", "#DA81F5"),name="MAC-\nStates",labels=c("TX-busy", "RX-busy", "IDLE", "Interference")) 

ggsave(p1, file="RegMon.png", width=11, height=8, dpi=600)
