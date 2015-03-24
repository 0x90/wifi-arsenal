#!/usr/bin/env Rscript

library(ggplot2)
library(reshape2)

args    <- commandArgs(TRUE)
csvfile <- args[[1]]
pfx     <- args[[2]]

base_rates <- function(df) {
  ncols <- length(df)
  nrows <- length(df[,1])
  delta_t <- (df[nrows,1] - df[1,1])
  dnames <- colnames(df)

  ret <- new.env()
  for (i in 2:ncols) {
    assign(dnames[i],
           (df[nrows,i] - df[1,i]) / delta_t,
           envir=ret)
  }
  ret
}

df <- as.data.frame(read.csv(csvfile, header=T))
bases <- base_rates(df)

df$time_seconds <- df$time_seconds - df$time_seconds[1]
df$dot11FCSErrorCount <- df$dot11FCSErrorCount - df$dot11FCSErrorCount[1]
df$received_fragment_count <- df$received_fragment_count - df$received_fragment_count[1]

df$dot11FCSErrorCount_vs_line <- df$dot11FCSErrorCount -
  (df$time_seconds * bases$dot11FCSErrorCount)
df$received_fragment_count_vs_line <- df$received_fragment_count -
  (df$time_seconds * bases$received_fragment_count)

df2 <- melt(df, id=c("time_seconds"),
            variable.name="Counter", value.name="Value",
            measure.vars=c("dot11FCSErrorCount", "received_fragment_count"))

p1 <- ggplot(df2, aes(x=time_seconds, y=Value, colour=Counter)) +
  geom_point() +
  stat_smooth() +
  theme(legend.position=c(1, 0),
        legend.justification=c(1,0)) +
  xlab("Time (s)") + ggtitle(csvfile)

# plot fraction of frames that are bad
dffrac <- data.frame(df$time_seconds)
colnames(dffrac)[1] <- "time_seconds"
dffrac$fraction_bad <- 100.0 * df$dot11FCSErrorCount / df$received_fragment_count
p2 <- ggplot(dffrac, aes(x=time_seconds, y=fraction_bad)) +
  geom_point(colour="red") +
  xlab("Time (s)") +
  ylab("dot11FCSErrorCount / received_fragment_count (%)") + ggtitle(csvfile)

df3 <- melt(df, id=c("time_seconds"),
            variable.name="Counter", value.name="Value",
            measure.vars=c("dot11FCSErrorCount_vs_line",
                           "received_fragment_count_vs_line"))

p3 <- ggplot(df3, aes(x=time_seconds, y=Value, colour=Counter)) +
  geom_point() +
  stat_smooth() +
  geom_hline(y=0, linetype=2) +
  theme(legend.position=c(1, 0),
        legend.justification=c(1,0)) +
  xlab("Time (s)") + ggtitle(csvfile)

ggsave(p1, file=paste(pfx, "_raw.pdf", sep=""),          width=8, height=5)
ggsave(p2, file=paste(pfx, "_fraction_bad.pdf", sep=""), width=8, height=5)
ggsave(p3, file=paste(pfx, "_vs_linear.pdf", sep=""),    width=8, height=5)
