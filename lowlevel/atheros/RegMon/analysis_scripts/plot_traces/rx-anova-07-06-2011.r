require(ggplot2)
require(xtable)


#Arbeitspfad setzen
setwd("/Volumes/cracker/data/nfs/thomas/experiments/rx-factor-anova-7.6.2011-sender=ma-cca-noiseimmu-weak-cali-channel-driver/data/merged-traces")

a-register <- read.csv(file="a-sender=ma-register.csv", header=TRUE, sep = " ")


#Anova Analyse
#1.) Normalverteilung pr√ºfen


#Histogramme erstellen

#ANOVA noise all
noise_model_all = aov(-noise ~ as.factor(weak)*as.factor(position), data = noise_all)
capture.output(summary(noise_model_all), file="anova_all_noise.doc")

noise_model_all_rxbusy = aov(rx.busy ~ as.factor(weak)*as.factor(position), data = noise_all)
capture.output(summary(noise_model_all_rxbusy), file="anova_all_rxbusy.doc")

noise_model_all_edbusy = aov(ed.busy ~ as.factor(weak)*as.factor(position), data = noise_all)
capture.output(summary(noise_model_all_edbusy), file="anova_all_edbusy.doc")







pdf("noise_eb.pdf") 
#par(mfrow = c(1,2))
histogram_eb_noise <- qplot(-noise, data=noise_eb, geom="histogram", binwidth=1, facets= rate ~ power)
histogram_eb_noise + opts(title='node:eb - noise histograms of all 4 groups of channel and calibration ')
interaction.plot(noise_eb$rate,noise_eb$calibration,-noise_eb$noise, legend = TRUE, xlab="channel", ylab="noise at EB", trace.label="calibration", main="interaction plot noise at EB")
dev.off()

pdf("noise_vwsf.pdf") 
histogram_vws <- qplot(-noise, data=noise_vws, geom="histogram", binwidth=1, facets= rate ~ power)
histogram_vws + opts(title='node:vws - noise histograms of all 4 groups of channel and calibration')
interaction.plot(noise_vws$channel,noise_vws$calibration,-noise_vws$noise, legend = TRUE, xlab="channel", ylab="noise at VWS", trace.label="calibration", main="interaction plot noise at VWS")
dev.off()

pdf("noise_ma.pdf") 
histogram_ma <- qplot(-noise, data=noise_ma, geom="histogram", binwidth=1, facets= rate ~ power)
histogram_ma + opts(title='node:ma - noise histograms of all 4 groups of channel and calibration')
interaction.plot(noise_ma$channel,noise_ma$calibration,-noise_ma$noise, legend = TRUE, xlab="channel", ylab="noise at MA", trace.label="calibration", main="interaction plot noise at MA")
dev.off()

#ed.busy is negative ---> error !!!!
#pdf("rx-busy_eb.pdf") 
#histogram_eb_rx <- qplot(rx.busy[rx.busy > 0], data=noise_eb, geom="histogram", binwidth=1, facets= channel ~ calibration)
#histogram_eb_rx + opts(title='node:eb - rx-busy histograms of all 4 groups of channel and calibration ')
#interaction.plot(noise_eb$channel,noise_eb$calibration,-noise_eb$rx.busy, legend = TRUE, xlab="channel", ylab="rx-busy at EB", trace.label="calibration", main="interaction plot rx-busy at EB")
#dev.off()


#ANOVA machen EB
noise_model_eb = aov(-noise ~ as.factor(rate)*as.factor(power), data = noise_eb)
capture.output(summary(noise_model_eb), file="anova_eb_noise.doc")

noise_model_eb_rxbusy = aov(rx.busy ~ as.factor(rate)*as.factor(power), data = noise_eb)
capture.output(summary(noise_model_eb_rxbusy), file="anova_eb_rxbusy.doc")

noise_model_eb_edbusy = aov(ed.busy ~ as.factor(rate)*as.factor(power), data = noise_eb)
capture.output(summary(noise_model_eb_edbusy), file="anova_eb_edbusy.doc")

#ANOVA machen VWS
noise_model_vws = aov(-noise ~ as.factor(rate)*as.factor(power), data = noise_vws)
capture.output(summary(noise_model_vws), file="anova_vws_noise.doc")

noise_model_vws_rxbusy = aov(-noise ~ as.factor(rate)*as.factor(power), data = noise_vws)
capture.output(summary(noise_model_vws_rxbusy), file="anova_vws_rxbusy.doc")

noise_model_vws_edbusy = aov(-noise ~ as.factor(rate)*as.factor(power), data = noise_vws)
capture.output(summary(noise_model_vws_edbusy), file="anova_vws_edbusy.doc")

#ANOVA machen MA
noise_model_ma = aov(-noise ~ as.factor(rate)*as.factor(power), data = noise_ma)
capture.output(summary(noise_model_ma), file="anova_ma_noise.doc")

noise_model_ma_rxbusy = aov(-noise ~ as.factor(rate)*as.factor(power), data = noise_ma)
capture.output(summary(noise_model_ma_rxbusy), file="anova_ma_rxbusy.doc")

noise_model_ma_edbusy = aov(-noise ~ as.factor(rate)*as.factor(power), data = noise_ma)
capture.output(summary(noise_model_ma_edbusy), file="anova_ma_edbusy.doc")

#residual histogramme

hist(noise_model_eb$res)
hist(noise_model_vws$res)

#plot residuals against fitted values to look for bvious trends that are not consistent with the model
delivery.res = histogram_eb
histogram_eb$M1.Fit = fitted(noise_model_eb)
histogram_eb$M1.Resid = resid(noise_model_eb)

#consider the normal probability plot of the model residuals, using the stat_qq() option:
p = qplot(sample = M1.Resid, data= histogram_eb) 
p + stat_qq()


ggplot(delivery.res, aes(M1.Fit, M1.Resid, colour = Service)) + 
  geom_point() +
  xlab("Fitted Values") + ylab("Residuals")






# stuff

#QQ Plot
qqplot_bib <- qplot(sample = -noise, data=noise_bib, facets = channel ~ calibration)
qqplot_bib + opts(title='node:bib - QQ-Plot from 64 groups ')

qqplot_eb <- qplot(sample = -noise, data=noise_eb, facets = channel ~ calibration)
qqplot_eb + opts(title='node:en - QQ-Plot from 64 groups ')

#interactive plot:
interaction.plot(noise_eb$rate,noise_eb$power,-noise_eb$noise, legend = TRUE, xlab="channel", ylab="noise at EB", trace.label="calibration", main="interaction plot noise at EB")
interaction.plot(noise_vws$rate,noise_vws$power,-noise_vws$noise, legend = TRUE, xlab="channel", ylab="noise at VWS", trace.label="calibration", main="interaction plot noise at VWS")

interaction.plot(noise_eb$rate,noise_eb$power,noise_eb$rx.busy, legend = TRUE, xlab="TX rate MA", ylab="noise at EB", trace.label="TX power MA", main="interaction plot noise at EB")
interaction.plot(noise_vws$rate,noise_vws$power,-noise_vws$rx.busy, legend = TRUE, xlab="TX rate MA", ylab="noise at VWS", trace.label="TX power MA", main="interaction plot noise at VWS")


density_vws <- qplot(-noise, data=noise_eb, geom="density", binwidth=1, facets= channel ~ calibration)
density_vws + opts(title='node:vws - noise densitys of all 4 groups of channel and calibration')

density_eb <- qplot(-noise, data=noise_eb, geom="density", binwidth=1, facets= channel ~ calibration)
density_eb + opts(title='node:eb - noise densitys of all 4 groups of channel and calibration')


noise_model_eb.table = xtable(noise_model_eb)
print(noise_model_eb.table, type="html")

noise_model_eb = aov(-noise ~ rate*power, data = noise_eb)

noise_model_eb.table = xtable(noise_model_eb)
print(noise_model_eb.table, type="html")