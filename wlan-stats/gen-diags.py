#!/usr/bin/python
#Hugh O'Brien 2014, obrien.hugh@gmail.com
# Run with: cd dest-dir; python gen_diags.py | R -q --vanilla

data_file = "/home/hugh/Dropbox/Thesis/wlan-proc/cap2.csv"
function = "density"
selector_column = "datarate"
data_column = "mpdu_duration"

graph_fmt = "png"
png_size=1000

datarates = [1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54]

print("x=read.csv('", data_file, "')", sep='')
for rate in datarates:
    output_file = function + "-of-" + data_column + "-at-" + str(rate) + "." + graph_fmt
    if graph_fmt == "png":
        print(graph_fmt, "(filename='", output_file,
                "',height=", png_size, ",width=", png_size, ",units='px')", sep='')
    if graph_fmt == "pdf":
        print(graph_fmt, "(filename='", output_file, "')", sep='')

    print("plot(", function, "(x[x$", selector_column, "=='", rate, "',]$", data_column, "))", sep='')
print("q()")
