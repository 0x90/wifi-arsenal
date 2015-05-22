#!/bin/bash

PCAP_FILES=( `ls $* | grep -v '\.fixed\.eps' | sed -e "s/att/_/g" | sort -t- -nk3 | sed -e "s/__/_att/g"` )
LATEX_DOCO=report.tex

cat  <<EOF > $LATEX_DOCO
\documentclass[a4paper,12pt]{article}
\usepackage{epsfig,subfigure}
\begin{document}
EOF

for f in ${PCAP_FILES[*]}; do 
	 ff="${f/28/27}"
	 if [[ -s $f && -s $ff ]]; then

	 l=`basename $f`
	 l="${l/.eps/}"
	 l="${l//_/ }"

	 cat <<EOF >> $LATEX_DOCO

\begin{figure}[ht]
  \centering
  \subfigure[traffic]{
    \includegraphics[width=65mm]{$f}
  }
  \subfigure[contention
  ]{
    \includegraphics[width=65mm]{$ff}
  }
  \caption{$l}
\end{figure}

EOF

	 fi
done

cat <<EOF >> $LATEX_DOCO
\end{document}
EOF
